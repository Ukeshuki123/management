const crypto = require('crypto');

// Generate a secure random string for JWT_SECRET
const secret = crypto.randomBytes(64).toString('hex');
console.log('Your secure JWT_SECRET:f191b97822f50e67a93781dd0e3ff60f7d073bddbb7ad2f7810ef1877c1813fcf23239289e1ce995b0a6532a63ed6b160900aca81de0d2edc0876cf84cf5fa01');
console.log(secret);
