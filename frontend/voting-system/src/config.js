/** 
 * Global configuration for the application 
 */ 
const CONFIG = { 
  API_URL: 'http://localhost:8080/api', 
  TOKEN_KEY: 'authToken', 
  ROUTES: { 
    HOME: '/index.html', 
    LOGIN: '/pages/auth/login.html', 
    REGISTER: '/pages/auth/register.html', 
    ADMIN: '/pages/admin/dashboard.html', 
    VOTER: '/pages/voting/vote.html' 
  } 
}; 

export default CONFIG;
