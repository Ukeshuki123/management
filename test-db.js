const mysql = require('mysql2/promise');
require('dotenv').config();

async function testDatabaseConnection() {
    let connection;
    try {
        const config = process.env.DATABASE_URL
            ? {
                uri: process.env.DATABASE_URL,
                ssl: {
                    rejectUnauthorized: true
                }
            }
            : {
                host: process.env.DB_HOST || 'localhost',
                user: process.env.DB_USER || 'root',
                password: process.env.DB_PASSWORD || 'Uki@12345',
                database: process.env.DB_NAME || 'employee_db'
            };

        const pool = process.env.DATABASE_URL
            ? mysql.createPool(config.uri)
            : mysql.createPool(config);

        connection = await pool.getConnection();
        console.log('✅ Database connection successful!');
        
        // Test query
        const [rows] = await pool.query('SELECT 1 as test');
        console.log('✅ Test query successful:', rows);
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    } finally {
        if (connection) {
            connection.release();
        }
    }
}

testDatabaseConnection();
