const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Fallback for development

// Database configuration
const dbConfig = process.env.DATABASE_URL
    ? {
        // Production configuration (using connection URL)
        uri: process.env.DATABASE_URL,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        ssl: {
            rejectUnauthorized: true
        }
    }
    : {
        // Local development configuration
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || 'Uki@12345',
        database: process.env.DB_NAME || 'employee_db',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    };

// Create the connection pool
const pool = process.env.DATABASE_URL
    ? mysql.createPool(dbConfig.uri)
    : mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log('Database connected successfully');
        connection.release();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// Test connection on startup
testConnection();

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Root path redirects to login
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// Serve login page
app.get('/login', (req, res) => {
    res.redirect('/login.html');
});

// Serve index page
app.get('/index', (req, res) => {
    res.redirect('/index.html');
});

// Serve employee page
app.get('/employee', (req, res) => {
    res.redirect('/employee.html');
});

// Serve checklist page
app.get('/checklist', (req, res) => {
    res.redirect('/checklist.html');
});

// Verify JWT token middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token is required' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        req.user = decoded;
        next();
    });
};

// Check authentication status
app.get('/api/check-auth', verifyToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            role: req.user.role,
            branch: req.user.branch
        }
    });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Query for user
        const [rows] = await pool.query(
            'SELECT id, username, password, role, branchname FROM employees WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const user = rows[0];

        // Compare password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Create token with user info
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                branch: user.branchname
            }, 
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send response
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                branch: user.branchname
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during login'
        });
    }
});

// Add new employee
app.post('/api/employees', verifyToken, async (req, res) => {
    try {
        const { username, password, role, branchname } = req.body;

        // Validate input
        if (!username || !password || !role || !branchname) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to add employees' });
        }

        // Management users can only add regular users
        if (req.user.role === 'management' && role !== 'user') {
            return res.status(403).json({ success: false, message: 'Management users can only add regular users' });
        }

        // Check if username already exists
        let connection;
        connection = await pool.getConnection();
        const [existingUser] = await connection.query(
            'SELECT id FROM employees WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            connection.release();
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new employee
        await connection.query(
            'INSERT INTO employees (username, password, role, branchname) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, branchname]
        );
        connection.release();
        res.json({ success: true, message: 'Employee added successfully' });
    } catch (error) {
        console.error('Error adding employee:', error);
        res.status(500).json({ success: false, message: 'Error adding employee' });
    }
});

// Get all employees
app.get('/api/employees', verifyToken, async (req, res) => {
    try {
        let query = 'SELECT id, username, role, branchname, created_at FROM employees';
        
        // If management user, only show regular users
        if (req.user.role === 'management') {
            query += " WHERE role = 'user'";
        }

        let connection;
        connection = await pool.getConnection();
        const [employees] = await connection.query(query);
        connection.release();
        res.json({ success: true, employees });
    } catch (error) {
        console.error('Error getting employees:', error);
        res.status(500).json({ success: false, message: 'Error getting employees' });
    }
});

// Delete employee
app.delete('/api/employees/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'management') {
            return res.status(403).json({ success: false, message: 'Unauthorized to delete employees' });
        }

        // Get employee details
        let connection;
        connection = await pool.getConnection();
        const [employee] = await connection.query(
            'SELECT role FROM employees WHERE id = ?',
            [id]
        );

        if (employee.length === 0) {
            connection.release();
            return res.status(404).json({ success: false, message: 'Employee not found' });
        }

        // Management users can only delete regular users
        if (req.user.role === 'management' && employee[0].role !== 'user') {
            connection.release();
            return res.status(403).json({ success: false, message: 'Management users can only delete regular users' });
        }

        await connection.query(
            'DELETE FROM employees WHERE id = ?',
            [id]
        );
        connection.release();
        res.json({ success: true, message: 'Employee deleted successfully' });
    } catch (error) {
        console.error('Error deleting employee:', error);
        res.status(500).json({ success: false, message: 'Error deleting employee' });
    }
});

// Get checklist questions
app.get('/api/checklist/questions', verifyToken, async (req, res) => {
    try {
        let connection;
        connection = await pool.getConnection();
        const [rows] = await connection.query(`
            SELECT id, section, question_text as question, question_type as type
            FROM checklist_questions
            ORDER BY section, id
        `);
        connection.release();
        res.json({
            success: true,
            questions: rows
        });
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch questions',
            error: error.message
        });
    }
});

// Submit checklist responses
app.post('/api/checklist/submit', verifyToken, async (req, res) => {
    try {
        const { responses } = req.body;
        const employeeId = req.user.id;

        for (const response of responses) {
            if (response.type === 'mcq') {
                await pool.query(
                    'INSERT INTO checklist_responses (employee_id, question_id, mcq_status) VALUES (?, ?, ?)',
                    [employeeId, response.question_id, response.status]
                );
            } else {
                await pool.query(
                    'INSERT INTO checklist_responses (employee_id, question_id, answer_text) VALUES (?, ?, ?)',
                    [employeeId, response.question_id, response.answer]
                );
            }
        }

        res.json({
            success: true,
            message: 'Responses submitted successfully'
        });
    } catch (error) {
        console.error('Error submitting responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit responses',
            error: error.message
        });
    }
});

// Get latest checklist responses (admin only)
app.get('/api/checklist/latest', verifyToken, async (req, res) => {
    try {
        // Check if user exists and is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }

        const isAdmin = userRows[0].role === 'admin';
        if (!isAdmin) {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        // Get latest responses with question and employee details
        const [responses] = await connection.query(`
            SELECT 
                cr.id,
                cr.question_id,
                cr.employee_id,
                cr.answer_text as answer,
                cr.mcq_status as status,
                cr.submitted_at as time,
                cq.question_text as question,
                cq.section,
                cq.question_type as type,
                e.username as employee_name,
                e.branchname as employee_branch
            FROM checklist_responses cr
            JOIN checklist_questions cq ON cr.question_id = cq.id
            JOIN employees e ON cr.employee_id = e.id
            WHERE cr.id IN (
                SELECT MAX(id)
                FROM checklist_responses
                GROUP BY question_id, employee_id
            )
            ORDER BY cr.submitted_at DESC
        `);
        connection.release();
        // Initialize response objects
        const byStatus = {
            yes: [],
            no: [],
            pending: []
        };

        const writtenResponses = {
            Kitchen: [],
            Cafe: []
        };

        // Process each response
        responses.forEach(row => {
            const response = {
                id: row.id,
                question_id: row.question_id,
                employee_id: row.employee_id,
                status: row.status?.toLowerCase() || 'pending',
                answer: row.answer || '',
                time: row.time,
                question: row.question,
                section: row.section,
                type: row.type,
                employee: row.employee_name,
                branch: row.employee_branch
            };

            if (row.type === 'written') {
                writtenResponses[row.section].push(response);
            } else {
                byStatus[response.status || 'pending'].push(response);
            }
        });

        res.json({
            success: true,
            byStatus,
            writtenResponses
        });
    } catch (error) {
        console.error('Error fetching latest responses:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch responses',
            error: error.message
        });
    }
});

// Delete response (admin only)
app.delete('/api/checklist/response/:id', verifyToken, async (req, res) => {
    try {
        // Check if user is admin
        let connection;
        connection = await pool.getConnection();
        const [userRows] = await connection.query(
            'SELECT role FROM employees WHERE username = ?',
            [req.user.username]
        );

        if (!userRows || userRows.length === 0 || userRows[0].role !== 'admin') {
            connection.release();
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const responseId = req.params.id;
        await connection.query('DELETE FROM checklist_responses WHERE id = ?', [responseId]);
        connection.release();
        res.json({
            success: true,
            message: 'Response deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting response:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete response',
            error: error.message
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
