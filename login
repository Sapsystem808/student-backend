// api/login.js
export default function handler(req, res) {
    // 1. استقبال كلمة السر القادمة من الموقع
    const { password } = req.body || req.query;

    // 2. إحضار كلمة السر الحقيقية من "الخزنة" (Environment Variables)
    const SECRET_PASSWORD = process.env.ADMIN_PASSWORD;

    // 3. المقارنة
    if (password === SECRET_PASSWORD) {
        return res.status(200).json({ success: true, message: "تم الدخول بنجاح" });
    } else {
        return res.status(401).json({ success: false, message: "كلمة المرور خاطئة" });
    }
}
