// File: server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Initialize Express app
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/jeemantra', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Database Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['student', 'teacher', 'admin'], default: 'student' },
    enrolledCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
    createdAt: { type: Date, default: Date.now }
});

const CourseSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    subject: { type: String, required: true },
    instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    thumbnail: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const LiveClassSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
    startTime: { type: Date, required: true },
    duration: { type: Number, required: true }, // in minutes
    meetingLink: { type: String, required: true },
    status: { type: String, enum: ['scheduled', 'live', 'completed'], default: 'scheduled' },
    recordedVideo: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const StudyMaterialSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
    type: { type: String, enum: ['pdf', 'video', 'ppt', 'doc'], required: true },
    fileUrl: { type: String, required: true },
    thumbnail: { type: String },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

const TestSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
    duration: { type: Number, required: true }, // in minutes
    startTime: { type: Date, required: true },
    endTime: { type: Date, required: true },
    totalMarks: { type: Number, required: true },
    questions: [{
        text: { type: String, required: true },
        options: [{ type: String }],
        correctAnswer: { type: Number, required: true },
        marks: { type: Number, default: 1 }
    }],
    results: [{
        student: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        score: { type: Number },
        submittedAt: { type: Date }
    }],
    status: { type: String, enum: ['scheduled', 'active', 'completed'], default: 'scheduled' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Course = mongoose.model('Course', CourseSchema);
const LiveClass = mongoose.model('LiveClass', LiveClassSchema);
const StudyMaterial = mongoose.model('StudyMaterial', StudyMaterialSchema);
const Test = mongoose.model('Test', TestSchema);

// Authentication Middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'jeemantrasecret');
        req.user = decoded;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /pdf|mp4|ppt|doc|docx/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) return cb(null, true);
        cb('Error: Only PDF, Video, and PPT files are allowed!');
    }
});

// Routes

// Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            name,
            email,
            password: hashedPassword,
            role: role || 'student'
        });

        await user.save();

        const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, 
            process.env.JWT_SECRET || 'jeemantrasecret', 
            { expiresIn: '7d' }
        );

        res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, 
            process.env.JWT_SECRET || 'jeemantrasecret', 
            { expiresIn: '7d' }
        );

        res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Course Routes
app.get('/api/courses', authenticate, async (req, res) => {
    try {
        const courses = await Course.find().populate('instructor', 'name');
        res.json(courses);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/courses', authenticate, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({ message: 'Only admins and teachers can create courses' });
        }

        const course = new Course({
            title: req.body.title,
            description: req.body.description,
            subject: req.body.subject,
            instructor: req.user.id
        });

        await course.save();
        res.status(201).json(course);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Live Class Routes
app.get('/api/live-classes', authenticate, async (req, res) => {
    try {
        const query = {};
        if (req.query.status) query.status = req.query.status;
        if (req.query.courseId) query.course = req.query.courseId;

        const liveClasses = await LiveClass.find(query)
            .populate('course', 'title subject')
            .sort({ startTime: 1 });
        
        res.json(liveClasses);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/live-classes', authenticate, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({ message: 'Only admins and teachers can schedule classes' });
        }

        const liveClass = new LiveClass({
            title: req.body.title,
            description: req.body.description,
            course: req.body.courseId,
            startTime: new Date(req.body.startTime),
            duration: req.body.duration,
            meetingLink: req.body.meetingLink,
            status: 'scheduled'
        });

        await liveClass.save();
        res.status(201).json(liveClass);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Study Material Routes
app.get('/api/study-materials', authenticate, async (req, res) => {
    try {
        const query = {};
        if (req.query.type) query.type = req.query.type;
        if (req.query.courseId) query.course = req.query.courseId;

        const materials = await StudyMaterial.find(query)
            .populate('course', 'title subject')
            .populate('uploadedBy', 'name')
            .sort({ createdAt: -1 });
        
        res.json(materials);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/study-materials', authenticate, upload.single('file'), async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({ message: 'Only admins and teachers can upload materials' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'File upload required' });
        }

        const material = new StudyMaterial({
            title: req.body.title,
            description: req.body.description,
            course: req.body.courseId,
            type: req.body.type,
            fileUrl: `/uploads/${req.file.filename}`,
            uploadedBy: req.user.id
        });

        await material.save();
        res.status(201).json(material);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Test Routes
app.get('/api/tests', authenticate, async (req, res) => {
    try {
        const query = {};
        if (req.query.status) query.status = req.query.status;
        if (req.query.courseId) query.course = req.query.courseId;

        const tests = await Test.find(query)
            .populate('course', 'title subject')
            .sort({ startTime: 1 });
        
        res.json(tests);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/tests/:id', authenticate, async (req, res) => {
    try {
        const test = await Test.findById(req.params.id)
            .populate('course', 'title subject');
        
        if (!test) return res.status(404).json({ message: 'Test not found' });

        // Don't send correct answers to students
        if (req.user.role === 'student') {
            const studentView = test.toObject();
            studentView.questions.forEach(q => delete q.correctAnswer);
            return res.json(studentView);
        }

        res.json(test);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/tests', authenticate, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({ message: 'Only admins and teachers can create tests' });
        }

        const test = new Test({
            title: req.body.title,
            description: req.body.description,
            course: req.body.courseId,
            duration: req.body.duration,
            startTime: new Date(req.body.startTime),
            endTime: new Date(req.body.endTime),
            totalMarks: req.body.questions.reduce((sum, q) => sum + (q.marks || 1), 0),
            questions: req.body.questions,
            status: 'scheduled'
        });

        await test.save();
        res.status(201).json(test);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.post('/api/tests/:id/submit', authenticate, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Only students can submit tests' });
        }

        const test = await Test.findById(req.params.id);
        if (!test) return res.status(404).json({ message: 'Test not found' });

        // Check if test is active
        const now = new Date();
        if (now < test.startTime || now > test.endTime) {
            return res.status(400).json({ message: 'Test is not currently active' });
        }

        // Check if student has already submitted
        const existingSubmission = test.results.find(r => r.student.equals(req.user.id));
        if (existingSubmission) {
            return res.status(400).json({ message: 'Test already submitted' });
        }

        // Calculate score
        let score = 0;
        req.body.answers.forEach((answer, index) => {
            if (answer === test.questions[index].correctAnswer) {
                score += test.questions[index].marks || 1;
            }
        });

        // Add result
        test.results.push({
            student: req.user.id,
            score,
            submittedAt: new Date()
        });

        await test.save();
        res.json({ score, totalMarks: test.totalMarks });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
