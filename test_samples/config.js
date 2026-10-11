const apiKey = "sk-live-9f8a7b6c5d4e";            // BAD
const DB_PASSWORD = 'Xk29fjs8dh3';                 // BAD
const settings = { "secret": "r7Tq92LmZpw1" };     // BAD
const password = "changeme";                       // placeholder: should NOT be reported
const token = process.env.API_TOKEN;               // SAFE: reads from the environment
