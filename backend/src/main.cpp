#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <vector>
#include <chrono>
#include <ctime>
#include <fstream>
#include <thread>
#include <mutex>

#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <regex>
#include <map>

#include "httplib.h"

using namespace httplib;

// Constants for security
const int MAX_LOGIN_ATTEMPTS = 5;
const int LOCKOUT_MINUTES = 15;
const int TOKEN_EXPIRY_MINUTES = 30;
const int PASSWORD_MIN_LENGTH = 8;

// In-memory session store: token -> {user_id, expiry_time}
struct SessionInfo {
    int user_id;
    std::chrono::time_point<std::chrono::system_clock> expiry;
    std::string user_ip;
};
static std::unordered_map<std::string, SessionInfo> sessions;

// Failed login tracking: user_id -> {attempts, lockout_time}
struct LoginAttempts {
    int count;
    std::chrono::time_point<std::chrono::system_clock> lockout_until;
};
static std::unordered_map<std::string, LoginAttempts> failed_logins;
static std::mutex login_mutex;

// Config
static std::string encryption_key;
static bool voting_open = true;

// Helper: SHA-256 → hex
std::string sha256(const std::string &in) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.c_str()), in.size(), hash);
    std::ostringstream os;
    for (auto b : hash) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return os.str();
}

// Helper: PBKDF2 for password hashing with salt
std::string pbkdf2_hash(const std::string &password, const std::string &salt, int iterations = 10000) {
    unsigned char key[32];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                      (unsigned char*)salt.c_str(), salt.length(),
                      iterations, EVP_sha256(), 32, key);
    
    std::ostringstream os;
    for (int i = 0; i < 32; i++) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    }
    return os.str();
}

// Helper: Base64 encode
std::string base64_encode(const std::string &in) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, in.c_str(), in.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

// Helper: Base64 decode
std::string base64_decode(const std::string &in) {
    BIO *bio, *b64;
    
    int decodeLen = in.size();
    std::vector<char> buffer(decodeLen);
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in.c_str(), in.length());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), in.length());
    BIO_free_all(bio);
    
    return std::string(buffer.data(), len);
}

// Helper: generate random hex token of length bytes*2
std::string random_token(size_t bytes=16) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), bytes);
    std::ostringstream os;
    for (auto b : buf) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return os.str();
}

// Helper: generate random salt
std::string generate_salt(size_t length=16) {
    return random_token(length);
}

// Helper: encrypt sensitive data
std::string encrypt_data(const std::string &plaintext, const std::string &key) {
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    RAND_bytes(iv.data(), AES_BLOCK_SIZE);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                      (unsigned char*)key.c_str(), iv.data());
    
    std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                     (unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    std::string result(iv.begin(), iv.end());
    result.append(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    
    return base64_encode(result);
}

// Helper: decrypt sensitive data
std::string decrypt_data(const std::string &ciphertext_b64, const std::string &key) {
    std::string ciphertext = base64_decode(ciphertext_b64);
    
    // Extract IV from the first AES_BLOCK_SIZE bytes
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                      (unsigned char*)key.c_str(), iv.data());
    
    std::vector<unsigned char> plaintext(ciphertext.length());
    int len = 0, plaintext_len = 0;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                     (unsigned char*)(ciphertext.data() + AES_BLOCK_SIZE), 
                     ciphertext.length() - AES_BLOCK_SIZE);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

// Helper: parse JSON-like body for one field (very naive!)
std::string extract_field(const std::string &body, const std::string &field) {
    auto pos = body.find("\"" + field + "\":");
    if (pos == std::string::npos) return {};
    auto start = body.find('"', pos + field.size()+3);
    if (start == std::string::npos) return {};
    auto end   = body.find('"', start+1);
    return body.substr(start+1, end - (start+1));
}

// Helper: write a JSON response
void json_res(Response &res, bool ok, const std::string &msg = "",
              const std::string &token = "") {
    res.set_header("Content-Type", "application/json");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-XSS-Protection", "1; mode=block");
    
    std::ostringstream out;
    out << "{ \"ok\": " << (ok ? "true" : "false");
    if (!msg.empty())   out << ", \"error\": \"" << msg << "\"";
    if (!token.empty()) out << ", \"token\": \"" << token << "\"";
    out << " }";
    res.set_content(out.str(), "application/json");
}

// Helper: Log activity
void log_activity(sqlite3 *db, const std::string &activity, int user_id = -1, 
                 const std::string &ip = "", bool success = true) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
      "INSERT INTO activity_log(user_id, ip_address, activity, success, timestamp) VALUES(?,?,?,?,datetime('now'));",
      -1, &st, nullptr);
    
    sqlite3_bind_int(st, 1, user_id);
    sqlite3_bind_text(st, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, activity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, success ? 1 : 0);
    
    sqlite3_step(st);
    sqlite3_finalize(st);
}

// Helper: Check if IDNP already voted
bool has_voted(sqlite3 *db, int user_id) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT 1 FROM votes WHERE user_id = ?;", -1, &st, nullptr);
    sqlite3_bind_int(st, 1, user_id);
    
    bool voted = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return voted;
}

// Helper: Check if IDNP exists
bool idnp_exists(sqlite3 *db, const std::string &idnp) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT 1 FROM users WHERE user = ?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, idnp.c_str(), -1, SQLITE_TRANSIENT);
    
    bool exists = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return exists;
}

// Helper: Check if user is valid voter
bool is_valid_voter(sqlite3 *db, const std::string &idnp) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT 1 FROM valid_voters WHERE idnp = ?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, idnp.c_str(), -1, SQLITE_TRANSIENT);
    
    bool valid = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return valid;
}

// Helper: Extract user ID from token
int get_user_id_from_token(const std::string &token) {
    auto it = sessions.find(token);
    if (it == sessions.end() || 
        it->second.expiry < std::chrono::system_clock::now()) {
        // Token expired
        if (it != sessions.end()) {
            sessions.erase(it); // Clean up expired token
        }
        return -1;
    }
    return it->second.user_id;
}

// Helper: Check password strength
bool is_strong_password(const std::string &password) {
    if (password.length() < PASSWORD_MIN_LENGTH) return false;
    
    bool has_upper = false, has_lower = false, 
         has_digit = false, has_special = false;
    
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }
    
    return has_upper && has_lower && has_digit && has_special;
}

// Session cleanup thread
void session_cleanup(std::unordered_map<std::string, SessionInfo> &sessions) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        
        auto now = std::chrono::system_clock::now();
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.expiry < now) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// Import physical votes
bool import_physical_votes(sqlite3 *db, const std::string &filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) return false;
    
    // Begin transaction
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    
    std::string line;
    int count = 0;
    
    // Skip header line
    std::getline(file, line);
    
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string idnp, choice;
        
        std::getline(ss, idnp, ',');
        std::getline(ss, choice, ',');
        
        // Validate data
        if (idnp.length() != 13 || (choice != "A" && choice != "B")) {
            continue;
        }
        
        // Check if valid voter
        if (!is_valid_voter(db, idnp)) {
            continue;
        }
        
        // Create user if not exists
        if (!idnp_exists(db, idnp)) {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db,
                "INSERT INTO users(user, pass, salt, physical_only) VALUES(?, ?, ?, 1);",
                -1, &st, nullptr);
            
            std::string salt = generate_salt();
            std::string dummy_pass = pbkdf2_hash("PhysicalVoter", salt);
            
            sqlite3_bind_text(st, 1, idnp.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, dummy_pass.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
            
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
        
        // Get user_id
        sqlite3_stmt *st_user;
        sqlite3_prepare_v2(db, "SELECT id FROM users WHERE user = ?;", -1, &st_user, nullptr);
        sqlite3_bind_text(st_user, 1, idnp.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_user) != SQLITE_ROW) {
            sqlite3_finalize(st_user);
            continue;
        }
        
        int user_id = sqlite3_column_int(st_user, 0);
        sqlite3_finalize(st_user);
        
        // Check if already voted
        if (has_voted(db, user_id)) {
            continue;
        }
        
        // Insert vote
        sqlite3_stmt *st_vote;
        sqlite3_prepare_v2(db,
            "INSERT INTO votes(user_id, choice, physical_vote) VALUES(?, ?, 1);",
            -1, &st_vote, nullptr);
        
        sqlite3_bind_int(st_vote, 1, user_id);
        sqlite3_bind_text(st_vote, 2, choice.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_vote) == SQLITE_DONE) {
            count++;
        }
        sqlite3_finalize(st_vote);
    }
    
    // Commit transaction
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    
    return true;
}

int main() {
    // 1) Open/create DB
    sqlite3 *db;
    if (sqlite3_open("votes.db", &db)) {
        std::cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
        return 1;
    }
    
    // 2) Init tables
    const char *init_sql = R"sql(
      CREATE TABLE IF NOT EXISTS users (
        id             INTEGER PRIMARY KEY,
        user           TEXT UNIQUE,
        pass           TEXT,
        salt           TEXT,
        email          TEXT,
        phone          TEXT,
        name           TEXT,
        recovery_code  TEXT,
        physical_only  INTEGER DEFAULT 0,
        created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS votes (
        id            INTEGER PRIMARY KEY,
        user_id       INTEGER UNIQUE,
        choice        TEXT,
        physical_vote INTEGER DEFAULT 0,
        ts            DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      
      CREATE TABLE IF NOT EXISTS activity_log (
        id          INTEGER PRIMARY KEY,
        user_id     INTEGER,
        ip_address  TEXT,
        activity    TEXT,
        success     INTEGER,
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      
      CREATE TABLE IF NOT EXISTS valid_voters (
        id           INTEGER PRIMARY KEY,
        idnp         TEXT UNIQUE,
        name         TEXT,
        voting_area  TEXT
      );
      
      CREATE TABLE IF NOT EXISTS password_reset (
        id           INTEGER PRIMARY KEY,
        user_id      INTEGER,
        reset_code   TEXT,
        expires      DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      
      CREATE INDEX IF NOT EXISTS idx_user_idnp ON users(user);
      CREATE INDEX IF NOT EXISTS idx_votes_user ON votes(user_id);
      CREATE INDEX IF NOT EXISTS idx_valid_voters ON valid_voters(idnp);
    )sql";
    
    sqlite3_exec(db, init_sql, nullptr, nullptr, nullptr);
    
    // Generate encryption key from random source or load from config
    encryption_key = sha256(random_token(32));
    
    // Start session cleanup thread
    std::thread cleanup_thread(session_cleanup, std::ref(sessions));
    cleanup_thread.detach();

    // 3) HTTP server
    Server svr;
    svr.set_mount_point("/", "../frontend");
    
    // Set timeout for connections
    svr.set_read_timeout(5, 0); // 5 seconds, 0 milliseconds
    svr.set_write_timeout(5, 0);
    
    // Add CORS headers for API access from different platforms
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type, Authorization"}
    });
    
    // Handler for OPTIONS requests (CORS preflight)
    svr.Options("/(.*)", [](const Request&, Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set_header("Access-Control-Max-Age", "86400");
        res.set_content("", "text/plain");
    });

    //
    // REGISTER
    //
    svr.Post("/register", [&](const Request& req, Response &res) {
        std::regex idnp_re("^[0-9]{13}$");
        // Get client IP
        auto client_ip = req.remote_addr;
        
        // grab form fields
        auto user = extract_field(req.body, "user");
        auto pass = extract_field(req.body, "pass");
        auto email = extract_field(req.body, "email");
        auto phone = extract_field(req.body, "phone");
        auto name = extract_field(req.body, "name");
        auto captcha = extract_field(req.body, "captcha");
    
        // 1. IDNP format
        if (!std::regex_match(user, idnp_re)) {
            log_activity(db, "registration attempt - invalid IDNP format", -1, client_ip, false);
            return json_res(res, false, "IDNP must be exactly 13 digits");
        }
        
        // 2. Captcha validation
        if (!std::regex_match(captcha, idnp_re)) {
            log_activity(db, "registration attempt - invalid captcha", -1, client_ip, false);
            return json_res(res, false, "Captcha must be exactly 13 numbers");
        }
        
        // 3. Required fields
        if (user.empty() || pass.empty()) {
            log_activity(db, "registration attempt - missing required fields", -1, client_ip, false);
            return json_res(res, false, "IDNP and password required");
        }
        
        // 4. Check if user exists
        if (idnp_exists(db, user)) {
            log_activity(db, "registration attempt - IDNP already exists", -1, client_ip, false);
            return json_res(res, false, "This IDNP is already registered");
        }
        
        // 5. Check if valid voter
        if (!is_valid_voter(db, user)) {
            log_activity(db, "registration attempt - not a valid voter", -1, client_ip, false);
            return json_res(res, false, "This IDNP is not registered in the voter database");
        }
        
        // 6. Password strength
        if (!is_strong_password(pass)) {
            log_activity(db, "registration attempt - weak password", -1, client_ip, false);
            return json_res(res, false, "Password must be at least 8 characters and include uppercase, lowercase, number, and special character");
        }
        
        // Generate salt and hash password
        std::string salt = generate_salt();
        std::string hashed = pbkdf2_hash(pass, salt);
        
        // Encrypt sensitive data
        std::string enc_email = email.empty() ? "" : encrypt_data(email, encryption_key);
        std::string enc_phone = phone.empty() ? "" : encrypt_data(phone, encryption_key);
        std::string enc_name = name.empty() ? "" : encrypt_data(name, encryption_key);
        
        // Generate recovery code
        std::string recovery_code = random_token(8);
        std::string hashed_recovery = sha256(recovery_code);
        
        // Insert user
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
          "INSERT INTO users(user, pass, salt, email, phone, name, recovery_code) VALUES(?,?,?,?,?,?,?);",
          -1, &st, nullptr);
        
        sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, enc_email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, enc_phone.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, enc_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, hashed_recovery.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            log_activity(db, "registration failed - database error", -1, client_ip, false);
            return json_res(res, false, "Registration failed (database error)");
        }
        
        // Get user ID for logging
        int user_id = sqlite3_last_insert_rowid(db);
        sqlite3_finalize(st);
        
        // Log successful registration
        log_activity(db, "registration successful", user_id, client_ip, true);
        
        // Create response with recovery code
        res.set_header("Content-Type", "application/json");
        res.set_content(
            "{ \"ok\": true, \"message\": \"Registration successful. Please save your recovery code.\", "
            "\"recovery_code\": \"" + recovery_code + "\" }",
            "application/json"
        );
    });

    //
    // LOGIN → issues session token
    //
    svr.Post("/login", [&](const Request& req, Response &res) {
        std::regex idnp_re("^[0-9]{13}$");
        auto client_ip = req.remote_addr;
        
        auto user = extract_field(req.body, "user");
        auto pass = extract_field(req.body, "pass");
        auto captcha = extract_field(req.body, "captcha");
    
        if (!std::regex_match(user, idnp_re)) {
            log_activity(db, "login attempt - invalid IDNP format", -1, client_ip, false);
            return json_res(res, false, "IDNP must be exactly 13 digits");
        }
        
        if (!std::regex_match(captcha, idnp_re)) {
            log_activity(db, "login attempt - invalid captcha", -1, client_ip, false);
            return json_res(res, false, "Captcha must be exactly 13 numbers");
        }
        
        if (user.empty() || pass.empty()) {
            log_activity(db, "login attempt - missing credentials", -1, client_ip, false);
            return json_res(res, false, "IDNP and password required");
        }
        
        // Check if account is locked due to failed attempts
        {
            std::lock_guard<std::mutex> lock(login_mutex);
            auto it = failed_logins.find(user);
            if (it != failed_logins.end() && 
                it->second.count >= MAX_LOGIN_ATTEMPTS && 
                it->second.lockout_until > std::chrono::system_clock::now()) {
                
                auto now = std::chrono::system_clock::now();
                auto lockout_mins = std::chrono::duration_cast<std::chrono::minutes>(
                    it->second.lockout_until - now).count();
                
                log_activity(db, "login attempt - account locked", -1, client_ip, false);
                return json_res(res, false, 
                    "Account temporarily locked. Try again in " + 
                    std::to_string(lockout_mins) + " minutes.");
            }
        }
        
        // Check if physical-only voter
        sqlite3_stmt *st_phys;
        sqlite3_prepare_v2(db,
            "SELECT physical_only FROM users WHERE user=?;",
            -1, &st_phys, nullptr);
        sqlite3_bind_text(st_phys, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_phys) == SQLITE_ROW) {
            int physical_only = sqlite3_column_int(st_phys, 0);
            if (physical_only == 1) {
                sqlite3_finalize(st_phys);
                log_activity(db, "login attempt - physical voter only", -1, client_ip, false);
                return json_res(res, false, "This voter has already voted in person at a physical location");
            }
        }
        sqlite3_finalize(st_phys);
        
        // Get salt and stored password hash
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT id, pass, salt FROM users WHERE user=?;",
            -1, &st, nullptr);
        sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st) == SQLITE_ROW) {
            int uid = sqlite3_column_int(st, 0);
            std::string stored_hash = 
                reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
            std::string salt = 
                reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
            
            // Hash the provided password with the stored salt
            std::string calculated_hash = pbkdf2_hash(pass, salt);
            
            if (calculated_hash == stored_hash) {
                sqlite3_finalize(st);
                
                // Reset failed login attempts
                {
                    std::lock_guard<std::mutex> lock(login_mutex);
                    failed_logins.erase(user);
                }
                
                // Create new token with expiration time
                auto token = random_token(16);
                auto expiry = std::chrono::system_clock::now() + 
                  std::chrono::minutes(TOKEN_EXPIRY_MINUTES);
                
                // Store session info
                sessions[token] = SessionInfo{uid, expiry, client_ip};
                
                // Log successful login
                log_activity(db, "login successful", uid, client_ip, true);
                
                return json_res(res, true, "", token);
            }
            
            // Failed login, increment counter
            {
                std::lock_guard<std::mutex> lock(login_mutex);
                auto &attempts = failed_logins[user];
                attempts.count++;
                
                // If max attempts reached, set lockout time
                if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
                    attempts.lockout_until = std::chrono::system_clock::now() + 
                      std::chrono::minutes(LOCKOUT_MINUTES);
                    
                    log_activity(db, "login failed - account locked", uid, client_ip, false);
                    sqlite3_finalize(st);
                    return json_res(res, false, 
                      "Too many failed attempts. Account locked for " + 
                      std::to_string(LOCKOUT_MINUTES) + " minutes.");
                }
            }
        }
        
        sqlite3_finalize(st);
        log_activity(db, "login failed - invalid credentials", -1, client_ip, false);
        return json_res(res, false, "Invalid credentials");
    });
    
    //
    // PASSWORD RESET REQUEST
    //
    svr.Post("/reset-request", [&](const Request& req, Response &res) {
        std::regex idnp_re("^[0-9]{13}$");
        auto client_ip = req.remote_addr;
        
        auto user = extract_field(req.body, "user");
        auto email = extract_field(req.body, "email");
        auto captcha = extract_field(req.body, "captcha");
        
        if (!std::regex_match(user, idnp_re)) {
            log_activity(db, "reset request - invalid IDNP format", -1, client_ip, false);
            return json_res(res, false, "IDNP must be exactly 13 digits");
        }
        
        if (!std::regex_match(captcha, idnp_re)) {
            log_activity(db, "reset request - invalid captcha", -1, client_ip, false);
            return json_res(res, false, "Captcha must be exactly 13 numbers");
        }
        
        // Find user
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT id, email FROM users WHERE user=?;",
            -1, &st, nullptr);
        sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            log_activity(db, "reset request - user not found", -1, client_ip, false);
            return json_res(res, false, "User not found");
        }
        
        int user_id = sqlite3_column_int(st, 0);
        std::string stored_email = 
            reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        sqlite3_finalize(st);
        
        // Verify email if provided (simplified, in real system would send email)
        if (!email.empty() && !stored_email.empty()) {
            std::string decrypted_email = decrypt_data(stored_email, encryption_key);
            if (email != decrypted_email) {
                log_activity(db, "reset request - email mismatch", user_id, client_ip, false);
                return json_res(res, false, "Email does not match");
            }
        }
        
        // Generate reset code
        std::string reset_code = random_token(8);
        std::string hashed_code = sha256(reset_code);
        
        // Delete any existing reset codes
        sqlite3_stmt *st_del;
        sqlite3_prepare_v2(db,
            "DELETE FROM password_reset WHERE user_id=?;",
            -1, &st_del, nullptr);
        sqlite3_bind_int(st_del, 1, user_id);
        sqlite3_step(st_del);
        sqlite3_finalize(st_del);
        
        // Insert new reset code
        sqlite3_stmt *st_ins;
        sqlite3_prepare_v2(db,
            "INSERT INTO password_reset(user_id, reset_code, expires) VALUES(?, ?, datetime('now', '+1 hour'));",
            -1, &st_ins, nullptr);
        sqlite3_bind_int(st_ins, 1, user_id);
        sqlite3_bind_text(st_ins, 2, hashed_code.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_ins) != SQLITE_DONE) {
            sqlite3_finalize(st_ins);
            log_activity(db, "reset request - database error", user_id, client_ip, false);
            return json_res(res, false, "Error generating reset code");
        }
        
        sqlite3_finalize(st_ins);
        log_activity(db, "reset request - code generated", user_id, client_ip, true);
        
        // In a real system, we would send this code via email or SMS
        // For demo, we'll return it directly
        res.set_header("Content-Type", "application/json");
        res.set_content(
            "{ \"ok\": true, \"message\": \"Reset code generated. In a real system, this would be sent to your email.\", "
            "\"reset_code\": \"" + reset_code + "\" }",
            "application/json"
        );
    });
    
    //
    // PASSWORD RESET CONFIRM
    //
    svr.Post("/reset-confirm", [&](const Request& req, Response &res) {
        std::regex idnp_re("^[0-9]{13}$");
        auto client_ip = req.remote_addr;
        
        auto user = extract_field(req.body, "user");
        auto code = extract_field(req.body, "code");
        auto new_pass = extract_field(req.body, "new_password");
        auto captcha = extract_field(req.body, "captcha");
        
        if (!std::regex_match(user, idnp_re)) {
            log_activity(db, "reset confirm - invalid IDNP format", -1, client_ip, false);
            return json_res(res, false, "IDNP must be exactly 13 digits");
        }
        
        if (!std::regex_match(captcha, idnp_re)) {
            log_activity(db, "reset confirm - invalid captcha", -1, client_ip, false);
            return json_res(res, false, "Captcha must be exactly 13 numbers");
        }
        
        if (code.empty() || new_pass.empty()) {
            log_activity(db, "reset confirm - missing fields", -1, client_ip, false);
            return json_res(res, false, "Reset code and new password required");
        }
        
        // Password strength
        if (!is_strong_password(new_pass)) {
            log_activity(db, "reset confirm - weak password", -1, client_ip, false);
            return json_res(res, false, "Password must be at least 8 characters and include uppercase, lowercase, number, and special character");
        }
        
        // Find user
        sqlite3_stmt *st_user;
        sqlite3_prepare_v2(db,
            "SELECT id FROM users WHERE user=?;",
            -1, &st_user, nullptr);
        sqlite3_bind_text(st_user, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_user) != SQLITE_ROW) {
            sqlite3_finalize(st_user);
            log_activity(db, "reset confirm - user not found", -1, client_ip, false);
            return json_res(res, false, "User not found");
        }
        
        int user_id = sqlite3_column_int(st_user, 0);
        sqlite3_finalize(st_user);
        
        // Check reset code
        std::string hashed_code = sha256(code);
        sqlite3_stmt *st_code;
        sqlite3_prepare_v2(db,
            "SELECT 1 FROM password_reset WHERE user_id=? AND reset_code=? AND expires > datetime('now');",
            -1, &st_code, nullptr);
        sqlite3_bind_int(st_code, 1, user_id);
        sqlite3_bind_text(st_code, 2, hashed_code.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st_code) != SQLITE_ROW) {
            sqlite3_finalize(st_code);
            log_activity(db, "reset confirm - invalid or expired code", user_id, client_ip, false);
            return json_res(res, false, "Invalid or expired reset code");
        }
        
        sqlite3_finalize(st_code);
        
        // Generate new salt and hash password
        std::string new_salt = generate_salt();
        std::string new_hash = pbkdf2_hash(new_pass, new_salt);
        
        // Update password
        sqlite3_stmt *st_update;
        sqlite3_prepare_v2(db,
            "UPDATE users SET pass=?, salt=? WHERE id=?;",
            -1, &st_update, nullptr);
        sqlite3_bind_text(st_update, 1, new_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st_update, 2, new_salt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st_update, 3, user_id);
        
        if (sqlite3_step(st_update) != SQLITE_DONE) {
            sqlite3_finalize(st_update);
            log_activity(db, "reset confirm - update failed", user_id, client_ip, false);
            return json_res(res, false, "Failed to update password");
        }
        
        sqlite3_finalize(st_update);
        
        // Delete reset code
        sqlite3_stmt *st_del;
        sqlite3_prepare_v2(db,
            "DELETE FROM password_reset WHERE user_id=?;",
            -1, &st_del, nullptr);
        sqlite3_bind_int(st_del, 1, user_id);
        sqlite3_step(st_del);
        sqlite3_finalize(st_del);
        
        // Invalidate any existing sessions
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.user_id == user_id) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        
        log_activity(db, "reset confirm - password updated", user_id, client_ip, true);
        return json_res(res, true, "Password has been reset successfully");
    });
    
    //
    // ACCOUNT RECOVERY WITH CODE
    //
    svr.Post("/recovery", [&](const Request& req, Response &res) {
        std::regex idnp_re("^[0-9]{13}$");
        auto client_ip = req.remote_addr;
        
        auto user = extract_field(req.body, "user");
        auto recovery_code = extract_field(req.body, "recovery_code");
        auto new_pass = extract_field(req.body, "new_password");
        auto captcha = extract_field(req.body, "captcha");
        
        if (!std::regex_match(user, idnp_re)) {
            log_activity(db, "recovery attempt - invalid IDNP format", -1, client_ip, false);
            return json_res(res, false, "IDNP must be exactly 13 digits");
        }
        
        if (!std::regex_match(captcha, idnp_re)) {
            log_activity(db, "recovery attempt - invalid captcha", -1, client_ip, false);
            return json_res(res, false, "Captcha must be exactly 13 numbers");
        }
        
        if (recovery_code.empty() || new_pass.empty()) {
            log_activity(db, "recovery attempt - missing fields", -1, client_ip, false);
            return json_res(res, false, "Recovery code and new password required");
        }
        
        // Password strength
        if (!is_strong_password(new_pass)) {
            log_activity(db, "recovery attempt - weak password", -1, client_ip, false);
            return json_res(res, false, "Password must be at least 8 characters and include uppercase, lowercase, number, and special character");
        }
        
        // Find user and check recovery code
        std::string hashed_recovery = sha256(recovery_code);
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT id FROM users WHERE user=? AND recovery_code=?;",
            -1, &st, nullptr);
        sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, hashed_recovery.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            log_activity(db, "recovery attempt - invalid code", -1, client_ip, false);
            return json_res(res, false, "Invalid recovery code");
        }
        
        int user_id = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        
        // Generate new salt and hash password
        std::string new_salt = generate_salt();
        std::string new_hash = pbkdf2_hash(new_pass, new_salt);
        
        // Generate new recovery code
        std::string new_recovery_code = random_token(8);
        std::string new_hashed_recovery = sha256(new_recovery_code);
        
        // Update password and recovery code
        sqlite3_stmt *st_update;
        sqlite3_prepare_v2(db,
            "UPDATE users SET pass=?, salt=?, recovery_code=? WHERE id=?;",
            -1, &st_update, nullptr);
        sqlite3_bind_text(st_update, 1, new_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st_update, 2, new_salt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st_update, 3, new_hashed_recovery.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st_update, 4, user_id);
        
        if (sqlite3_step(st_update) != SQLITE_DONE) {
            sqlite3_finalize(st_update);
            log_activity(db, "recovery attempt - update failed", user_id, client_ip, false);
            return json_res(res, false, "Failed to update password");
        }
        
        sqlite3_finalize(st_update);
        
        // Invalidate any existing sessions
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.user_id == user_id) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        
        log_activity(db, "recovery successful", user_id, client_ip, true);
        
        // Return new recovery code
        res.set_header("Content-Type", "application/json");
        res.set_content(
            "{ \"ok\": true, \"message\": \"Account recovered successfully. Please save your new recovery code.\", "
            "\"recovery_code\": \"" + new_recovery_code + "\" }",
            "application/json"
        );
    });

    //
    // VOTE → protected by Bearer token
    //
    svr.Post("/vote", [&](const Request& req, Response &res) {
        auto client_ip = req.remote_addr;
        
        // Check if voting is open
        if (!voting_open) {
            return json_res(res, false, "Voting is currently closed");
        }
        
        // 1) auth header
        auto auth = req.get_header_value("Authorization");
        if (auth.rfind("Bearer ", 0) != 0) {
            log_activity(db, "vote attempt - missing auth", -1, client_ip, false);
            return json_res(res, false, "Missing or invalid auth header");
        }
        
        auto token = auth.substr(7);
        auto user_id = get_user_id_from_token(token);
        
        if (user_id == -1) {
            log_activity(db, "vote attempt - invalid token", -1, client_ip, false);
            return json_res(res, false, "Invalid or expired token");
        }
        
        // Check if user's IP matches login IP (prevent session hijacking)
        auto it = sessions.find(token);
        if (it->second.user_ip != client_ip) {
            // Log suspicious activity
            log_activity(db, "vote attempt - IP mismatch", user_id, client_ip, false);
            // Invalidate session
            sessions.erase(it);
            return json_res(res, false, "Session invalid. Please login again.");
        }

        // 2) choice
        auto choice = extract_field(req.body, "choice");
        if (choice != "A" && choice != "B") {
            log_activity(db, "vote attempt - invalid choice", user_id, client_ip, false);
            return json_res(res, false, "Invalid choice");
        }

        // 3) Check if already voted
        if (has_voted(db, user_id)) {
            log_activity(db, "vote attempt - already voted", user_id, client_ip, false);
            return json_res(res, false, "You have already voted");
        }

        // 4) Insert vote
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "INSERT INTO votes(user_id, choice) VALUES(?,?);",
            -1, &st, nullptr);
        sqlite3_bind_int(st, 1, user_id);
        sqlite3_bind_text(st, 2, choice.c_str(), -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            log_activity(db, "vote failed - database error", user_id, client_ip, false);
            return json_res(res, false, "Vote failed to register");
        }
        
        sqlite3_finalize(st);
        log_activity(db, "vote successful", user_id, client_ip, true);
        return json_res(res, true, "Vote recorded successfully");
    });

    // 
    // CHECK VOTER STATUS
    //
    svr.Get("/status", [&](const Request& req, Response &res) {
        // Auth header
        auto auth = req.get_header_value("Authorization");
        if (auth.rfind("Bearer ", 0) != 0) {
            return json_res(res, false, "Missing or invalid auth header");
        }
        
        auto token = auth.substr(7);
        auto user_id = get_user_id_from_token(token);
        
        if (user_id == -1) {
            return json_res(res, false, "Invalid or expired token");
        }
        
        // Check if already voted
        bool voted = has_voted(db, user_id);
        
        // Get choice if voted
        std::string choice;
        if (voted) {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db,
                "SELECT choice, physical_vote FROM votes WHERE user_id = ?;",
                -1, &st, nullptr);
            sqlite3_bind_int(st, 1, user_id);
            
            if (sqlite3_step(st) == SQLITE_ROW) {
                choice = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
                int physical = sqlite3_column_int(st, 1);
                
                if (physical == 1) {
                    choice = "Physical vote: " + choice;
                }
            }
            sqlite3_finalize(st);
        }
        
        // Return status
        res.set_header("Content-Type", "application/json");
        std::ostringstream out;
        out << "{ \"ok\": true, \"has_voted\": " << (voted ? "true" : "false");
        if (voted && !choice.empty()) {
            out << ", \"choice\": \"" << choice << "\"";
        }
        out << " }";
        res.set_content(out.str(), "application/json");
    });

    //
    // RESULTS
    //
    svr.Get("/results", [&](const Request& req, Response &res) {
        // Authentication required to view results
        auto auth = req.get_header_value("Authorization");
        if (auth.rfind("Bearer ", 0) != 0) {
            return json_res(res, false, "Authentication required to view results");
        }
        
        auto token = auth.substr(7);
        if (get_user_id_from_token(token) == -1) {
            return json_res(res, false, "Invalid or expired token");
        }
        
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT choice, physical_vote, COUNT(*) AS cnt FROM votes GROUP BY choice, physical_vote;",
            -1, &st, nullptr);
        
        std::map<std::string, int> results;
        std::map<std::string, int> physical_results;
        std::map<std::string, int> online_results;
        
        while (sqlite3_step(st) == SQLITE_ROW) {
            std::string choice = 
                reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            int physical = sqlite3_column_int(st, 1);
            int count = sqlite3_column_int(st, 2);
            
            results[choice] += count;
            
            if (physical == 1) {
                physical_results[choice] += count;
            } else {
                online_results[choice] += count;
            }
        }
        sqlite3_finalize(st);
        
        // Get total voter count
        sqlite3_stmt *st_total;
        sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM valid_voters;",
            -1, &st_total, nullptr);
        
        int total_voters = 0;
        if (sqlite3_step(st_total) == SQLITE_ROW) {
            total_voters = sqlite3_column_int(st_total, 0);
        }
        sqlite3_finalize(st_total);
        
        // Get total votes
        sqlite3_stmt *st_votes;
        sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM votes;",
            -1, &st_votes, nullptr);
        
        int total_votes = 0;
        if (sqlite3_step(st_votes) == SQLITE_ROW) {
            total_votes = sqlite3_column_int(st_votes, 0);
        }
        sqlite3_finalize(st_votes);
        
        // Build JSON response
        std::ostringstream js;
        js << "{ \"ok\": true, \"results\": {";
        bool first = true;
        for (auto &p : results) {
            if (!first) js << ", ";
            first = false;
            js << "\"" << p.first << "\": " << p.second;
        }
        
        js << "}, \"physical_votes\": {";
        first = true;
        for (auto &p : physical_results) {
            if (!first) js << ", ";
            first = false;
            js << "\"" << p.first << "\": " << p.second;
        }
        
        js << "}, \"online_votes\": {";
        first = true;
        for (auto &p : online_results) {
            if (!first) js << ", ";
            first = false;
            js << "\"" << p.first << "\": " << p.second;
        }
        
        js << "}, \"stats\": { ";
        js << "\"total_voters\": " << total_voters;
        js << ", \"total_votes\": " << total_votes;
        js << ", \"participation\": " << (total_voters > 0 ? 
             (total_votes * 100.0 / total_voters) : 0);
        js << "} }";
        
        res.set_header("Content-Type", "application/json");
        res.set_content(js.str(), "application/json");
    });
    
    //
    // LOGOUT
    //
    svr.Post("/logout", [&](const Request& req, Response &res) {
        auto auth = req.get_header_value("Authorization");
        if (auth.rfind("Bearer ", 0) != 0) {
            return json_res(res, false, "Invalid request");
        }
        
        auto token = auth.substr(7);
        auto it = sessions.find(token);
        
        if (it != sessions.end()) {
            int user_id = it->second.user_id;
            sessions.erase(it);
            log_activity(db, "logout", user_id, req.remote_addr, true);
            return json_res(res, true, "Logged out successfully");
        }
        
        return json_res(res, false, "Invalid session");
    });
    
    //
    // ADMIN ENDPOINTS (would require proper role-based access control in production)
    //
    
    // Import physical votes
    svr.Post("/admin/import-physical", [&](const Request& req, Response &res) {
        // In a real system, this would be protected by admin authentication
        
        auto filepath = extract_field(req.body, "filepath");
        if (filepath.empty()) {
            return json_res(res, false, "Filepath required");
        }
        
        if (import_physical_votes(db, filepath)) {
            return json_res(res, true, "Physical votes imported successfully");
        } else {
            return json_res(res, false, "Failed to import physical votes");
        }
    });
    
    // Register valid voters
    svr.Post("/admin/register-voters", [&](const Request& req, Response &res) {
        // In a real system, this would be protected by admin authentication
        
        auto filepath = extract_field(req.body, "filepath");
        if (filepath.empty()) {
            return json_res(res, false, "Filepath required");
        }
        
        std::ifstream file(filepath);
        if (!file.is_open()) {
            return json_res(res, false, "Could not open file");
        }
        
        // Begin transaction
        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
        
        std::string line;
        int count = 0;
        
        // Skip header line
        std::getline(file, line);
        
        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string idnp, name, area;
            
            std::getline(ss, idnp, ',');
            std::getline(ss, name, ',');
            std::getline(ss, area, ',');
            
            // Validate IDNP
            if (idnp.length() != 13) {
                continue;
            }
            
            // Insert voter
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db,
                "INSERT OR IGNORE INTO valid_voters(idnp, name, voting_area) VALUES(?, ?, ?);",
                -1, &st, nullptr);
            
            sqlite3_bind_text(st, 1, idnp.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, area.c_str(), -1, SQLITE_TRANSIENT);
            
            if (sqlite3_step(st) == SQLITE_DONE) {
                count++;
            }
            sqlite3_finalize(st);
        }
        
        // Commit transaction
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
        
        return json_res(res, true, "Registered " + std::to_string(count) + " voters");
    });
    
    // Toggle voting status
    svr.Post("/admin/toggle-voting", [&](const Request& req, Response &res) {
        // In a real system, this would be protected by admin authentication
        
        voting_open = !voting_open;
        return json_res(res, true, 
            std::string("Voting is now ") + (voting_open ? "open" : "closed"));
    });

    std::cout << "Secure Voting Server listening on http://localhost:8080\n";
    svr.listen("0.0.0.0", 8080);

    sqlite3_close(db);
    return 0;
}