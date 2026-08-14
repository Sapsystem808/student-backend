
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');

let serviceAccount;
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
        serviceAccount = require('./serviceAccountKey.json');
    }
} catch (error) {
    console.error("❌ Service Account Error - Check Env Vars", error);
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
    process.env.SUPABASE_URL || "",
    process.env.SUPABASE_SERVICE_ROLE_KEY || ""
);

const helmet = require('helmet');
const app = express();
app.set('trust proxy', 1);
app.use(helmet());

const rateLimit = require('express-rate-limit');
const { Ratelimit } = require('@upstash/ratelimit');
const { Redis } = require('@upstash/redis');

let registerRatelimit = null;
try {
    registerRatelimit = new Ratelimit({
        redis: Redis.fromEnv(),
        limiter: Ratelimit.slidingWindow(5, '15 m'),
        analytics: true,
        prefix: 'ratelimit:registerStudent',
    });
} catch (e) {
    console.error('⚠️ Upstash init failed for register:', e.message);
}
const registerFallbackLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "⏳ محاولات تسجيل كثيرة، حاول بعد شوية" }
});

const registerStudentLimiter = async (req, res, next) => {
    if (!registerRatelimit) return registerFallbackLimiter(req, res, next);
    try {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
        const { success } = await registerRatelimit.limit(ip);
        if (!success) {
            return res.status(429).json({ error: "⏳ محاولات تسجيل كثيرة، حاول بعد شوية" });
        }
        next();
    } catch (e) {
        console.error('⚠️ registerRatelimit runtime error — falling back to local limiter:', e.message);
        registerFallbackLimiter(req, res, next); 
    }
};

let checkIdRatelimit = null;
try {
    checkIdRatelimit = new Ratelimit({
        redis: Redis.fromEnv(),
        limiter: Ratelimit.slidingWindow(8, '10 s'),
        analytics: true,
        prefix: 'ratelimit:checkStudentId',
    });
} catch (e) {
    console.error('⚠️ Upstash init failed — falling back to local rate limiter:', e.message);
}

const checkIdFallbackLimiter = rateLimit({
    windowMs: 10 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'rate_limited' }
});

const STUDENT_ID_SAFE_PATTERN = /^[A-Za-z0-9]{4,20}$/;

app.use(cors({
    origin: function (origin, callback) {
        const isLocal = !origin || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
        const isProd = origin === 'https://smartattendancepro-code.github.io'
            || origin === 'https://smart-attendance-pro-sap.web.app'
            || origin === 'https://smart-attendance-pro-sap.firebaseapp.com';

        if (isLocal || isProd) {
            callback(null, true);
        } else {
            console.warn('🚫 CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(bodyParser.json({ limit: '100kb' }));

const COLLEGE_COORDS = {
    lat: 30.385873919506743,
    lng: 30.488794680472196
};
const MAX_DISTANCE_KM = 2.5;

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Missing Token" });
    }
    try {
        const idToken = authHeader.split('Bearer ')[1];
        req.user = await admin.auth().verifyIdToken(idToken);
        next();
    } catch (error) {
        return res.status(403).json({ error: "Invalid Token" });
    }
};

const verifyStaffRole = async (req, res, next) => {
    try {
        const uid = req.user.uid;
        // ابحث عن المستخدم في مجموعة الدكاترة ب Firestore
        const docSnap = await db.collection("faculty_members").doc(uid).get();

        if (docSnap.exists) {
            const userData = docSnap.data();
            if (userData.role === 'dean' || userData.role === 'doctor') {
                return next(); // مسموح له بالمرور
            }
        }

        return res.status(403).json({ error: "Access Denied: Staff Only" });
    } catch (e) {
        res.status(500).json({ error: "Security Check Failed" });
    }
};

function calculateDistance(lat1, lon1, lat2, lon2) {
    if (!lat1 || !lon1 || !lat2 || !lon2) return 9999;
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

app.get('/', (req, res) => {
    res.status(200).send("🦅 Nursing System Backend is Running (Bulletproof V6)");
});


app.post('/api/student-enroll', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { subjectDocId, subjectName, studentId, studentName, studentGroup } = req.body;

        if (!subjectDocId || !studentId || !studentName) {
            return res.status(400).json({ error: "بيانات التسجيل غير مكتملة." });
        }

        const subjectRef = db.collection('subject_enrollments').doc(subjectDocId);

        let collegeForSignal = null;

        await db.runTransaction(async (transaction) => {
            const subjectSnap = await transaction.get(subjectRef);

            if (!subjectSnap.exists) {
                throw Object.assign(new Error("المادة غير موجودة أو تم حذفها."), { statusCode: 404 });
            }

            const subjectData = subjectSnap.data();
            collegeForSignal = subjectData.college || null;
            if (subjectData.isOpenForSelfEnrollment !== true) {
                throw Object.assign(
                    new Error("عذراً، قام أستاذ المادة بإغلاق باب التسجيل."),
                    { statusCode: 403 }
                );
            }
            const currentStudents = subjectData.students || [];
            const isAlreadyEnrolled = currentStudents.some(
                s => String(s.id).trim() === String(studentId).trim()
            );

            if (isAlreadyEnrolled) {
                throw Object.assign(
                    new Error("لقد قمت بالتسجيل في هذه المادة مسبقاً!"),
                    { statusCode: 409 }
                );
            }

            const newStudentObj = {
                id: String(studentId).trim(),
                name: String(studentName).trim(),
                group: String(studentGroup || '').trim(),
                enrolledBySelf: true,
                uid: studentUID,
                timestamp: new Date().toISOString()
            };

            transaction.update(subjectRef, {
                students: admin.firestore.FieldValue.arrayUnion(newStudentObj),
                studentIds: admin.firestore.FieldValue.arrayUnion(String(studentId).trim()),
                studentCount: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        if (collegeForSignal) {
            try {
                await db.collection('enrollment_signals').doc(collegeForSignal).set({
                    lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
                    lastAction: 'enrollment',
                    subjectId: subjectDocId
                }, { merge: true });
            } catch (signalErr) {
                console.warn("⚠️ Signal update skipped:", signalErr.message);
            }
        }

        console.log(`✅ Student Enrolled | ID: ${studentId} | Subject: ${subjectName}`);

        return res.status(200).json({
            success: true,
            message: "تم التسجيل في المادة بنجاح."
        });

    } catch (error) {
        const status = error.statusCode || 500;
        const msg = error.statusCode
            ? error.message
            : "حدث خطأ في الخادم، يرجى المحاولة لاحقاً.";

        if (!error.statusCode) {
            console.error("Enrollment API Error:", error);
        }

        return res.status(status).json({ error: msg });
    }
});

app.post('/joinSessionSecure', verifyToken, async (req, res) => {
    const perfStart = Date.now();
    try {
        const studentUID = req.user.uid;
        const { sessionDocID, gpsLat, gpsLng, deviceFingerprint, codeInput, patternPath } = req.body;

        const attemptRef = db.collection('rate_limits').doc(studentUID);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;

        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - data.updatedAt?.toMillis()) > 60_000;
            if (expired) {
                await attemptRef.delete();
            } else {
                attempts = data.attempts || 0;
            }
        }

        if (attempts >= 3) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }
        const userIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        if (!sessionDocID) return res.status(400).json({ error: "Missing Session ID" });
        const sessionRef = db.collection('active_sessions').doc(sessionDocID);
        const studentRef = db.collection('user_registrations').doc(studentUID);
        const sensitiveRef = db.collection('user_registrations').doc(studentUID).collection('sensitive_info').doc('main');
        const participantRef = sessionRef.collection('participants').doc(studentUID);

        const [sessionSnap, studentSnap, sensitiveSnap, participantSnap] = await Promise.all([
            sessionRef.get(),
            studentRef.get(),
            sensitiveRef.get(),
            participantRef.get()
        ]);
        if (!sessionSnap.exists) return res.status(404).json({ error: "⛔ الجلسة غير موجودة." });
        if (!studentSnap.exists) return res.status(404).json({ error: "بيانات الطالب غير موجودة." });

        const sessionData = sessionSnap.data();
        const sData = studentSnap.data();
        const info = sData.registrationInfo || {};

        const isEmailVerified = req.user.email_verified; // حالة تفعيل جوجل
        const isManuallyVerified = (sData.status === 'verified' || sData.manual_verification === true); // حالة التفعيل اليدوي من القاعدة

        if (!isEmailVerified && !isManuallyVerified) {
            return res.status(403).json({ error: "⛔ الحساب غير مفعل! يرجى تأكيد الإيميل أو مراجعة شؤون الطلاب." });
        }
        if (!sessionData.isActive || !sessionData.isDoorOpen) {
            return res.status(403).json({ error: "🔒 الباب مغلق حالياً." });
        }
        if (sessionData.sessionPassword) {
            try {
                const serverPass = JSON.parse(sessionData.sessionPassword);
                if (serverPass?.type === 'pattern') {
                    const { patternPath } = req.body;
                    if (!patternPath || !Array.isArray(patternPath) || patternPath.length < 3) {
                        return res.status(403).json({ error: "❌ النمط مطلوب للدخول" });
                    }
                    const serverPath = serverPass.path.map(p =>
                        Number(Object.keys(serverPass.mapping).find(k => serverPass.mapping[k] === p))
                    );
                    const isMatch = serverPath.length === patternPath.length &&
                        serverPath.every((v, i) => v === patternPath[i]);
                    if (!isMatch) {
                        return res.status(403).json({ error: "❌ النمط غير صحيح" });
                    }
                }
            } catch (e) {
                return res.status(403).json({ error: "❌ خطأ في التحقق من النمط" });
            }
        }

        if (!codeInput || String(codeInput).trim() === "") {
            return res.status(400).json({ error: "❌ كود الجلسة مطلوب." });
        }

        if (!sessionData.sessionCode ||
            String(codeInput).trim() !== String(sessionData.sessionCode).trim()) {
            return res.status(403).json({ error: "❌ كود الجلسة خاطئ." });
        }
        let currentDist = calculateDistance(gpsLat, gpsLng, COLLEGE_COORDS.lat, COLLEGE_COORDS.lng);
        let isLocationValid = (currentDist <= MAX_DISTANCE_KM);

        let isDeviceMatch = true;
        const batch = db.batch();

        if (sensitiveSnap.exists) {
            const sensData = sensitiveSnap.data();
            const allowed = sensData.allowed_devices || (sensData.bound_device_id ? [sensData.bound_device_id] : []);

            if (deviceFingerprint && !allowed.includes(deviceFingerprint)) {
                isDeviceMatch = false;
            }
        } else {
            batch.set(sensitiveRef, {
                allowed_devices: [deviceFingerprint || "UNKNOWN_DEVICE"],
                bound_at: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
        }

        const trapReport = {
            is_in_range: isLocationValid,
            is_device_match: isDeviceMatch,
            gps_success: (gpsLat !== 0 && gpsLng !== 0),
            distance_km: Number(currentDist.toFixed(3)),
            ip_address: userIP,
            device_id_used: deviceFingerprint || "NO_ID",
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            process_time_ms: Date.now() - perfStart
        };

        let savedCount = participantSnap.exists ? (participantSnap.data().segment_count || 1) : 1;

        batch.set(participantRef, {
            id: info.studentID || "UNKNOWN",
            name: info.fullName || "Student",
            uid: studentUID,
            level: info.level || "-",
            group: info.group || "-",
            status: "active",
            isSuspicious: !isDeviceMatch,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            trap_report: trapReport,
            avatarClass: sData.avatarClass || "fa-user",
            isUnruly: false,
            isUniformViolation: false,
            segment_count: savedCount
        });
        const subjectKey = (sessionData.allowedSubject || "General").replace(/[^\w\u0600-\u06FF]/g, '_');
        const statsRef = db.collection('student_stats').doc(studentUID);

        batch.set(statsRef, {
            [`attended.${subjectKey}`]: admin.firestore.FieldValue.increment(1),
            last_attendance: admin.firestore.FieldValue.serverTimestamp(),
            fullName: info.fullName,
            studentID: info.studentID,
            group: info.group || "عام"
        }, { merge: true });
        batch.update(studentRef, {
            attendanceCount: admin.firestore.FieldValue.increment(1)
        });

        await batch.commit();

        console.log(`⚡ FastJoin: ${Date.now() - perfStart}ms | User: ${info.fullName}`);

        await attemptRef.delete();

        try {
            await db.collection('user_registrations').doc(studentUID).set({
                liveState: {
                    status: 'active',
                    doctorUID: sessionDocID,
                    joinedAt: admin.firestore.FieldValue.serverTimestamp()
                }
            }, { merge: true });
        } catch (e) {
            console.warn('liveState update skipped:', e.message);
        }

        res.status(200).json({ success: true, message: "تم تسجيل الحضور ✅" });

    } catch (error) {
        console.error("🔥 Join Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر حاول مجدداً" });
    }
});

app.post('/api/checkStudentId', checkIdFallbackLimiter, async (req, res) => {
    try {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';

        if (checkIdRatelimit) {
            const { success } = await checkIdRatelimit.limit(ip);
            if (!success) {
                res.setHeader('Retry-After', '10');
                return res.status(429).json({ error: 'rate_limited' });
            }
        }

        const { studentId } = req.body || {};
        if (typeof studentId !== 'string' || !STUDENT_ID_SAFE_PATTERN.test(studentId)) {
            return res.status(400).json({ status: 'not_found' });
        }

        const cleanID = studentId.trim();

        const [lockSnap, stdSnap] = await Promise.all([
            db.collection('taken_student_ids').doc(cleanID).get(),
            db.collection('students').doc(cleanID).get(),
        ]);

        if (lockSnap.exists) {
            return res.status(200).json({ status: 'taken' });
        }

        if (!stdSnap.exists) {
            return res.status(200).json({ status: 'not_found' });
        }

        return res.status(200).json({
            status: 'ok',
            name: stdSnap.data().name,
        });

    } catch (e) {
        console.error('❌ checkStudentId Error:', e);
        return res.status(500).json({ error: 'internal_error' });
    }
});

app.post('/api/registerStudent', registerStudentLimiter, async (req, res) => {


    let createdUserUID = null;
    let reservationMade = false;
    let cleanID = null;

    try {
        let { email, password, fullName, studentID, level, gender, group, deviceFingerprint } = req.body;

        if (!studentID || !email || !password || !fullName || !level || !gender) {
            return res.status(400).json({ error: "بيانات ناقصة! يرجى ملء جميع الحقول المطلوبة." });
        }
        cleanID = studentID.toString().trim();
        const cleanEmail = email.toString().trim().toLowerCase();
        const cleanName = fullName.toString().trim();

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(cleanEmail)) {
            return res.status(400).json({ error: "صيغة البريد الإلكتروني غير صحيحة" });
        }

        if (!password || password.toString().length < 8) {
            return res.status(400).json({ error: "كلمة المرور يجب أن تكون 8 أحرف على الأقل" });
        }

        let finalGroup = "عام";

        if (group && group.trim() !== "") {
            const groupUpper = group.toString().toUpperCase().trim();

            const groupPattern = /^[1-4][GPNCDTBHEAMVIL]\d{1,2}$/;


            if (!groupPattern.test(groupUpper)) {
                return res.status(400).json({
                    error: "صيغة الجروب غير صحيحة. مثال: 1G1 أو 2P3 أو 3N1"

                });
            }

            if (level && !groupUpper.startsWith(level.toString())) {
                return res.status(400).json({
                    error: `تضارب البيانات: اخترت الفرقة ${level} ولكن الجروب ${groupUpper} يتبع فرقة أخرى!`
                });
            }

            finalGroup = groupUpper;
        } else {
            finalGroup = "عام";
        }
        const officialStudentSnap = await db.collection("students").doc(cleanID).get();
        if (!officialStudentSnap.exists) {
            return res.status(404).json({ error: "❌ هذا الكود الجامعي غير مسجل في كشوف الكلية" });
        }

        const idRef = db.collection("taken_student_ids").doc(cleanID);
        try {
            await db.runTransaction(async (tx) => {
                const idSnap = await tx.get(idRef);
                if (idSnap.exists) {
                    throw Object.assign(new Error("هذا الكود الجامعي مسجل بالفعل!"), { statusCode: 409 });
                }
                tx.create(idRef, {
                    status: 'reserved',
                    reservedAt: admin.firestore.FieldValue.serverTimestamp()
                });
            });
        } catch (e) {
            return res.status(e.statusCode || 500).json({ error: e.message });
        }
        reservationMade = true;

        const userRecord = await admin.auth().createUser({
            email: cleanEmail,
            password: password,
            displayName: cleanName,
            emailVerified: false
        });

        createdUserUID = userRecord.uid;

        await admin.auth().setCustomUserClaims(createdUserUID, {
            role: 'student',
            studentID: cleanID
        });

        const batch = db.batch();

        batch.set(db.collection("user_registrations").doc(createdUserUID), {
            registrationInfo: {
                fullName: cleanName,
                studentID: cleanID,
                level: level.toString(),
                gender: gender,
                group: finalGroup
            },
            role: "student",
            attendanceCount: 0,
            avatarClass: "fa-user-graduate",
            status: "pending_verification",
            accountCreated: admin.firestore.FieldValue.serverTimestamp()
        });
        const safeFP = deviceFingerprint || "UNKNOWN_DEVICE";

        batch.set(db.collection("user_registrations").doc(createdUserUID).collection("sensitive_info").doc("main"), {
            email: cleanEmail,
            bound_device_id: safeFP,
            created_via: "Secure_Backend_V3"
        });

        await batch.commit();

        createdUserUID = null;

        res.status(200).json({ success: true, uid: userRecord.uid });

    } catch (error) {
        console.error("❌ Registration Failed:", error);

        if (createdUserUID) {
            console.log(`⚠️ Rolling back... Deleting orphaned user: ${createdUserUID}`);
            try {
                await admin.auth().deleteUser(createdUserUID);
                console.log("✅ Rollback Successful: Orphaned account deleted.");
            } catch (rollbackError) {
                console.error("💀 CRITICAL: Rollback failed! Manually check UID:", createdUserUID);
            }
        }
        if (reservationMade && cleanID) {
            try {
                await db.collection("taken_student_ids").doc(cleanID).delete();
                console.log("✅ Reservation released.");
            } catch (relErr) {
                console.error("💀 CRITICAL: Reservation cleanup failed for ID:", cleanID);
            }
        }
        if (error.code === 'auth/email-already-in-use') {
            return res.status(409).json({ error: "البريد الإلكتروني مستخدم بالفعل" });
        }
        if (error.code === 'auth/invalid-email') {
            return res.status(400).json({ error: "صيغة البريد الإلكتروني غير صحيحة" });
        }
        if (error.code === 'auth/weak-password') {
            return res.status(400).json({ error: "كلمة المرور ضعيفة جداً" });
        }

        res.status(500).json({ error: "فشل التسجيل: " + error.message });
    }
});
// 🧹 تنظيف الحسابات غير المفعّلة اللي عدّت على إنشاءها أكتر من 48 ساعة
// بتتنفذ تلقائيًا عبر Vercel Cron — بتحرر الأرقام الجامعية المحجوزة بدون تفعيل
app.get('/api/cleanupUnverifiedAccounts', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        const cutoff = Date.now() - (48 * 60 * 60 * 1000); // 48 ساعة
        const cutoffTimestamp = admin.firestore.Timestamp.fromMillis(cutoff);

        const staleSnap = await db.collection('user_registrations')
            .where('status', '==', 'pending_verification')
            .where('accountCreated', '<', cutoffTimestamp)
            .get();

        if (staleSnap.empty) {
            return res.status(200).json({ success: true, cleaned: 0 });
        }

        let cleanedCount = 0;
        for (const docSnap of staleSnap.docs) {
            const uid = docSnap.id;
            const data = docSnap.data();
            const studentID = data.registrationInfo?.studentID;

            try {
                await admin.auth().deleteUser(uid);
            } catch (e) {
                console.warn(`⚠️ Auth delete skipped for ${uid}:`, e.message);
            }

            const batch = db.batch();
            batch.delete(db.collection('user_registrations').doc(uid));
            batch.delete(db.collection('user_registrations').doc(uid).collection('sensitive_info').doc('main'));
            if (studentID) {
                batch.delete(db.collection('taken_student_ids').doc(studentID));
            }
            await batch.commit();
            cleanedCount++;
        }

        console.log(`🧹 Cleaned ${cleanedCount} unverified accounts`);
        res.status(200).json({ success: true, cleaned: cleanedCount });

    } catch (error) {
        console.error("❌ Cleanup Error:", error);
        res.status(500).json({ error: "فشل التنظيف" });
    }
});


app.get('/api/config', (req, res) => {
    res.json({
        authDomain: "attendance-system-pro-dbdf1.firebaseapp.com",
        projectId: "attendance-system-pro-dbdf1",
        messagingSenderId: "1094544109334",
        appId: "1:1094544109334:web:a7395159d617b3e6e82a37"
    });
});

app.post('/api/verifyOfflinePattern', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, patternPath } = req.body;

        if (!sessionPin || !patternPath) {
            return res.status(400).json({ error: "بيانات ناقصة" });
        }

        const attemptRef = db.collection('rate_limits').doc(studentUID);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;

        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - data.updatedAt?.toMillis()) > 60_000;
            if (expired) {
                await attemptRef.delete();
            } else {
                attempts = data.attempts || 0;
            }
        }

        if (attempts >= 2) {
            return res.status(429).json({
                error: "⛔ تجاوزت عدد المحاولات",
                attemptsLeft: 0
            });
        }
        const codeSnap = await db
            .collection('issued_codes_logs')
            .doc(sessionPin)
            .get();

        if (!codeSnap.exists) {
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }

        const codeData = codeSnap.data();
        const sessionPassword = codeData.sessionPassword;
        if (!sessionPassword) {
            return res.status(200).json({
                success: true,
                verifyToken: 'NO_PATTERN'
            });
        }
        const serverPass = JSON.parse(sessionPassword);

        if (serverPass?.type === 'pattern') {
            if (!Array.isArray(patternPath) || patternPath.length < 3) {
                return res.status(403).json({ error: "❌ النمط مطلوب" });
            }

            let isMatch = false;
            if (serverPass.mapping) {
                const mappedStudentPath = patternPath.map(
                    idx => serverPass.mapping[idx]
                );
                isMatch = JSON.stringify(mappedStudentPath) ===
                    JSON.stringify(serverPass.path);
            } else {
                isMatch = JSON.stringify(patternPath) ===
                    JSON.stringify(serverPass.path);
            }

            if (!isMatch) {
                await attemptRef.set({
                    attempts: admin.firestore.FieldValue.increment(1),
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                }, { merge: true });

                return res.status(403).json({
                    error: "❌ النمط غير صحيح",
                    attemptsLeft: 2 - (attempts + 1)
                });
            }
        }

        const crypto = require('crypto');
        const verifyToken = crypto.randomBytes(32).toString('hex');
        await db.collection('pattern_tokens')
            .doc(`${studentUID}_${sessionPin}`)
            .set({
                token: verifyToken,
                sessionPin: sessionPin,
                expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 30_000)
            });

        await attemptRef.delete();

        res.status(200).json({ success: true, verifyToken });

    } catch (e) {
        console.error('Offline pattern verify error:', e);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

app.post('/api/syncPostSessionAttendance', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, submissionTime } = req.body;
        if (typeof sessionPin !== 'string' || !/^\d{6}$/.test(sessionPin)) {
            return res.status(400).json({ error: "كود الجلسة غير صالح" });
        }
        if (typeof submissionTime !== 'number' || submissionTime <= 0 || submissionTime > Date.now() + 5000) {
            return res.status(400).json({ error: "وقت التسجيل غير صالح" });
        }

        const attemptRef = db.collection('rate_limits').doc(`postsync_${studentUID}`);
        const [attemptSnap, studentSnap, codeSnap] = await Promise.all([
            attemptRef.get(),
            db.collection('user_registrations').doc(studentUID).get(),
            db.collection('issued_codes_logs').doc(sessionPin).get()
        ]);

        let attempts = 0;
        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - (data.updatedAt?.toMillis() || 0)) > 60_000;
            if (expired) {
                await attemptRef.delete();
            } else {
                attempts = data.attempts || 0;
            }
        }
        if (attempts >= 5) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }
        if (!studentSnap.exists) {
            return res.status(404).json({ error: "بيانات الطالب غير موجودة" });
        }
        const sData = studentSnap.data();
        const info = sData.registrationInfo || sData;
        const studentID = String(info.studentID || sData.studentID || '').trim();
        if (!studentID) {
            return res.status(403).json({ error: "رقم جامعي غير موثق" });
        }

        if (!codeSnap.exists) {
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }
        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;
        if (!doctorUID) {
            return res.status(500).json({ error: "بيانات الجلسة تالفة" });
        }
        const college = /^[A-Za-z0-9_]+$/.test(codeData.college || '') ? codeData.college : "NURS";
        const rawSubject = (codeData.subject || "General").toString();

        if (codeData.sessionPassword) {
            const tokenSnap = await db.collection('pattern_tokens')
                .doc(`${studentUID}_${sessionPin}`)
                .get();

            const tokenValid = tokenSnap.exists &&
                tokenSnap.data().expiresAt.toMillis() > submissionTime;

            if (!tokenValid) {
                return res.status(403).json({ error: "❌ التحقق من النمط مطلوب أو انتهت صلاحيته" });
            }
        }

        const sessionSnap = await db.collection('active_sessions').doc(doctorUID).get();
        const sessionData = sessionSnap.exists ? sessionSnap.data() : {};

        if (sessionData.isActive === true && sessionData.sessionCode === sessionPin) {
            return res.status(409).json({ error: "الجلسة لسه مفتوحة، استخدم المسار العادي" });
        }

        const openedAtMs = codeData.openedAt?.toMillis
            ? codeData.openedAt.toMillis()
            : Number(codeData.openedAt) || 0;
        const OFFLINE_WINDOW_MS = 25_000;
        const LOOSE_DRIFT = 4000;

        if (submissionTime < (openedAtMs - LOOSE_DRIFT) || submissionTime > (openedAtMs + OFFLINE_WINDOW_MS + LOOSE_DRIFT)) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(403).json({ error: "❌ خارج نافذة التسجيل المسموحة" });
        }
        const subDate = new Date(submissionTime);
        const d = String(subDate.getDate()).padStart(2, '0');
        const m = String(subDate.getMonth() + 1).padStart(2, '0');
        const y = subDate.getFullYear();
        const dateKey = `${d}-${m}-${y}`;
        const fixedDateStr = `${d}/${m}/${y}`;
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');
        const recID = `${studentID}_${dateKey}_${cleanSubKey}`;

        const payload = {
            id: studentID,
            sessionPin,
            name: info.fullName || sData.fullName || "Student",
            subject: rawSubject,
            college,
            hall: codeData.hall || "Hall",
            group: info.group || "GENERAL",
            date: fixedDateStr,
            time_str: subDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
            timestamp: admin.firestore.Timestamp.fromMillis(submissionTime),
            status: "ATTENDED",
            doctorUID,
            doctorName: codeData.doctorName || "Doctor",
            notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)",
            isOfflineSync: true,
            isPostSession: true,
            feedback_status: "pending",
            feedback_rating: 0,
        };

        const batch = db.batch();

        batch.set(db.collection('attendance').doc(recID), payload);


        batch.set(db.collection('offline_attendance_log').doc(recID), {
            studentID, sessionPin, submissionTime, studentUID,
            syncTimestamp: admin.firestore.FieldValue.serverTimestamp(),
            syncStatus: "SUCCESS_POST_SESSION_BACKEND_V3"
        });

        batch.set(db.collection('student_stats').doc(studentUID), {
            [`attended.${cleanSubKey}`]: admin.firestore.FieldValue.increment(1),
            last_attendance: admin.firestore.FieldValue.serverTimestamp(),
            fullName: payload.name,
            studentID: studentID,
            group: payload.group,
            college: college
        }, { merge: true });

        batch.set(db.collection('user_registrations').doc(studentUID), {
            pendingFeedback: {
                attendanceDocId: recID,
                subject: rawSubject,
                doctorName: codeData.doctorName || "Doctor",
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            }
        }, { merge: true });

        await Promise.all([
            batch.commit(),
            attemptRef.delete().catch(() => { })
        ]);

        console.log(`✅ Post-Session Sync | Student: ${studentID} | Doctor: ${doctorUID} | PIN: ${sessionPin}`);

        try {
            const { error: supErr } = await supabase
                .from('attendance_logs')
                .upsert([{
                    student_id: studentID,
                    student_name: payload.name,
                    subject_name: rawSubject,
                    college: college,
                    hall: codeData.hall || "",
                    target_group: payload.group,
                    sis_code: codeData.sisCode || "",
                    session_date: fixedDateStr,
                    attendance_time: payload.time_str,
                    status: "ATTENDED",
                    is_unruly: false,
                    is_uniform_violation: false,
                    notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)",
                    doctor_uid: doctorUID,
                    doctor_name: codeData.doctorName || "Doctor",
                    is_recovered: false,
                    feedback_status: "pending",
                    feedback_rating: 0,
                    segment_count: 1,
                    is_offline_sync: true,
                    level: info.level || "-",
                    group_name: payload.group,
                    is_suspicious: false,
                    trap_is_in_range: null,
                    trap_is_device_match: null,
                    trap_gps_success: null,
                    trap_distance_km: null,
                }], {
                    onConflict: 'student_id,subject_name,session_date,doctor_uid'

                });

            if (supErr) console.error("❌ Supabase sync error:", supErr);
            else console.log(`✅ Supabase synced | Student: ${studentID} | PIN: ${sessionPin}`);
        } catch (supEx) {
            console.error("❌ Supabase exception:", supEx.message);
        }

        res.status(200).json({ success: true, recID });

    } catch (error) {
        console.error("❌ syncPostSessionAttendance Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر، حاول مجدداً" });
    }
});

app.post('/api/syncFeedback', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { studentId, doctorUID, subject, date, rating } = req.body;

        if (!studentId || !doctorUID || !subject || !date || !rating) {
            return res.status(400).json({ error: "بيانات ناقصة" });
        }

        const { error, data } = await supabase
            .from('attendance_logs')
            .update({
                feedback_status: 'submitted',
                feedback_rating: parseInt(rating)
            })
            .match({
                student_id: studentId,
                doctor_uid: doctorUID,
                subject_name: subject,
                session_date: date
            })
            .select();

        if (error) {
            console.error("❌ Supabase Feedback Sync Error:", error);
            return res.status(500).json({ error: error.message });
        }

        console.log(`✅ Feedback synced | Student: ${studentId} | UID: ${studentUID} | Rating: ${rating} | Rows: ${data?.length || 0}`);
        res.status(200).json({ success: true, updated: data?.length || 0 });

    } catch (e) {
        console.error("❌ syncFeedback Exception:", e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/syncLiveOfflineAttendance', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, submissionTime, patternInput, offlineVerifyToken } = req.body;

        if (typeof sessionPin !== 'string' || !/^\d{6}$/.test(sessionPin)) {
            return res.status(400).json({ error: "كود الجلسة غير صالح" });
        }
        if (typeof submissionTime !== 'number' || submissionTime <= 0 || submissionTime > Date.now() + 5000) {
            return res.status(400).json({ error: "وقت التسجيل غير صالح" });
        }

        const attemptRef = db.collection('rate_limits').doc(`livesync_${studentUID}`);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;
        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - (data.updatedAt?.toMillis() || 0)) > 60_000;
            if (expired) await attemptRef.delete();
            else attempts = data.attempts || 0;
        }
        if (attempts >= 5) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }

        const studentSnap = await db.collection('user_registrations').doc(studentUID).get();
        if (!studentSnap.exists) return res.status(404).json({ error: "بيانات الطالب غير موجودة" });
        const sData = studentSnap.data();
        const info = sData.registrationInfo || sData;
        const studentID = String(info.studentID || sData.studentID || '').trim();
        if (!studentID) return res.status(403).json({ error: "رقم جامعي غير موثق" });

        const codeSnap = await db.collection('issued_codes_logs').doc(sessionPin).get();
        if (!codeSnap.exists) return res.status(404).json({ error: "❌ كود غير صحيح" });
        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;
        if (!doctorUID) return res.status(500).json({ error: "بيانات الجلسة تالفة" });
        const college = /^[A-Za-z0-9_]+$/.test(codeData.college || '') ? codeData.college : "NURS";
        const rawSubject = (codeData.subject || "General").toString();

        const sessionSnap = await db.collection('active_sessions').doc(doctorUID).get();
        const sessionData = sessionSnap.exists ? sessionSnap.data() : {};
        if (!(sessionData.isActive === true && sessionData.sessionCode === sessionPin)) {
            return res.status(409).json({ error: "الجلسة مقفولة، استخدم مسار ما بعد الجلسة" });
        }

        if (codeData.sessionPassword) {
            if (!offlineVerifyToken || !patternInput) {
                return res.status(403).json({ error: "بيانات الباترن ناقصة" });
            }
            const tokenSnap = await db.collection('pattern_tokens')
                .doc(`${studentUID}_${sessionPin}`).get();
            const tokenValid = tokenSnap.exists &&
                tokenSnap.data().token === offlineVerifyToken &&
                tokenSnap.data().expiresAt.toMillis() > submissionTime;
            if (!tokenValid) {
                return res.status(403).json({ error: "❌ التحقق من النمط مطلوب أو انتهت صلاحيته" });
            }
        }

        const openedAtMs = codeData.openedAt?.toMillis
            ? codeData.openedAt.toMillis()
            : Number(codeData.openedAt) || 0;
        const OFFLINE_WINDOW_MS = 25_000;
        const LOOSE_DRIFT = 4000;
        if (submissionTime < (openedAtMs - LOOSE_DRIFT) || submissionTime > (openedAtMs + OFFLINE_WINDOW_MS + LOOSE_DRIFT)) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(403).json({ error: "❌ خارج نافذة التسجيل المسموحة" });
        }

        const subDate = new Date(submissionTime);
        const d = String(subDate.getDate()).padStart(2, '0');
        const m = String(subDate.getMonth() + 1).padStart(2, '0');
        const y = subDate.getFullYear();
        const dateKey = `${d}-${m}-${y}`;
        const fixedDateStr = `${d}/${m}/${y}`;
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');
        const recID = `${studentID}_${dateKey}_${cleanSubKey}`;

        const payload = {
            id: studentID,
            sessionPin,
            name: info.fullName || sData.fullName || "Student",
            subject: rawSubject,
            college,
            hall: codeData.hall || "Hall",
            group: info.group || "GENERAL",
            date: fixedDateStr,
            time_str: subDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
            timestamp: admin.firestore.Timestamp.fromMillis(submissionTime),
            status: "ATTENDED",
            doctorUID,
            doctorName: codeData.doctorName || "Doctor",
            notes: "منضبط (أوفلاين - أثناء الجلسة)",
            isOfflineSync: true,
            feedback_status: "pending",
            feedback_rating: 0,
        };

        const batch = db.batch();
        batch.set(db.collection('attendance').doc(recID), payload);
        batch.set(db.collection(`attendance_${college}`).doc(recID), payload);
        batch.set(db.collection('active_sessions').doc(doctorUID).collection('participants').doc(studentUID), {
            id: studentID, uid: studentUID, name: payload.name,
            status: "active", timestamp: admin.firestore.FieldValue.serverTimestamp(),
            isOfflineSync: true, submissionTime
        });
        batch.set(db.collection('offline_attendance_log').doc(recID), {
            studentID, sessionPin, submissionTime, studentUID,
            syncTimestamp: admin.firestore.FieldValue.serverTimestamp(),
            syncStatus: "SUCCESS_LIVE_BACKEND_V1"
        });

        await Promise.all([batch.commit(), attemptRef.delete().catch(() => { })]);

        res.status(200).json({ success: true, recID });

    } catch (error) {
        console.error("❌ syncLiveOfflineAttendance Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر، حاول مجدداً" });
    }
});


if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🛡️ Server Running Port ${PORT}`));
}
module.exports = app;