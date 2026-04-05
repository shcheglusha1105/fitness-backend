const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Подключение к базе данных
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ===================== ЮKASSA НАСТРОЙКИ =====================
const YOOKASSA_SHOP_ID = process.env.YOOKASSA_SHOP_ID;
const YOOKASSA_SECRET_KEY = process.env.YOOKASSA_SECRET_KEY;

// Функция для создания платежа в ЮKassa
async function createYookassaPayment(amount, description, returnUrl, metadata) {
    const auth = Buffer.from(`${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`).toString('base64');
    const idempotenceKey = crypto.randomUUID();
    
    const response = await fetch('https://api.yookassa.ru/v3/payments', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Idempotence-Key': idempotenceKey,
            'Authorization': `Basic ${auth}`
        },
        body: JSON.stringify({
            amount: {
                value: amount,
                currency: 'RUB'
            },
            payment_method_data: {
                type: 'bank_card'
            },
            confirmation: {
                type: 'redirect',
                return_url: returnUrl
            },
            description: description,
            capture: true,
            metadata: metadata
        })
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        console.error('YooKassa API error:', errorText);
        throw new Error(`YooKassa error: ${response.status}`);
    }
    
    return await response.json();
}

// ===================== СОЗДАНИЕ ПЛАТЕЖА =====================
app.post('/api/create-payment', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Не авторизован' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;
        
        const payment = await createYookassaPayment(
            '300.00',
            'PRO подписка Фитнес-помощник на 365 дней',
            `${process.env.APP_URL}/payment-success.html`,
            { userId: userId.toString() }
        );
        
        if (payment.confirmation && payment.confirmation.confirmation_url) {
            res.json({ confirmation_url: payment.confirmation.confirmation_url });
        } else {
            console.error('Invalid payment response:', payment);
            res.status(500).json({ error: 'Ошибка создания платежа' });
        }
    } catch (err) {
        console.error('Payment error:', err);
        res.status(500).json({ error: 'Ошибка создания платежа' });
    }
});

// ===================== WEBHOOK ДЛЯ ЮKASSA =====================
app.post('/api/yookassa-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const event = req.body;
    
    console.log('Webhook received:', event);
    
    if (event.object && event.object.status === 'succeeded') {
        const userId = event.object.metadata?.userId;
        if (userId) {
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 365);
            
            try {
                await pool.query(
                    'UPDATE users SET subscription = $1, pro_expires_at = $2 WHERE id = $3',
                    ['pro', expiresAt.toISOString(), userId]
                );
                console.log(`✅ PRO активирован для пользователя ${userId} до ${expiresAt.toISOString()}`);
            } catch (err) {
                console.error('Error updating user subscription:', err);
            }
        }
    }
    
    res.json({ ok: true });
});

// ===================== ПРОВЕРКА СТАТУСА PRO =====================
app.get('/api/check-pro', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Не авторизован' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query(
            'SELECT subscription, pro_expires_at FROM users WHERE id = $1',
            [decoded.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        const user = result.rows[0];
        const isPro = user.subscription === 'pro' && new Date(user.pro_expires_at) > new Date();
        
        res.json({
            isPro: isPro,
            expires_at: user.pro_expires_at,
            subscription: user.subscription
        });
    } catch (err) {
        console.error('Check pro error:', err);
        res.status(401).json({ error: 'Неверный токен' });
    }
});

// ===================== РЕГИСТРАЦИЯ =====================
app.post('/api/register', async (req, res) => {
    const { email, password, name, surname, age, weight } = req.body;
    
    if (!email || !password || !name || !surname || !age || !weight) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            `INSERT INTO users (email, password, name, surname, age, weight, verified) 
             VALUES ($1, $2, $3, $4, $5, $6, true) 
             RETURNING id, email, name, surname, created_at`,
            [email, hashedPassword, name, surname, age, weight]
        );
        
        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error('Register error:', err);
        if (err.code === '23505') {
            res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        } else {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
});

// ===================== ВХОД =====================
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Пользователь не найден' });
        }
        
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(400).json({ error: 'Неверный пароль' });
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                surname: user.surname,
                email: user.email,
                subscription: user.subscription
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ===================== МИДЛВЭР АВТОРИЗАЦИИ =====================
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Не авторизован' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(401).json({ error: 'Неверный токен' });
    }
};

// ===================== ПОЛУЧЕНИЕ ДАННЫХ ПОЛЬЗОВАТЕЛЯ =====================
app.get('/api/user/data', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT menu, exercises, checklist, workout_days FROM user_data WHERE user_id = $1',
            [req.userId]
        );
        
        if (result.rows.length === 0) {
            res.json({ menu: null, exercises: null, checklist: null, workout_days: null });
        } else {
            res.json(result.rows[0]);
        }
    } catch (err) {
        console.error('Get data error:', err);
        res.status(500).json({ error: 'Ошибка загрузки данных' });
    }
});

// ===================== СОХРАНЕНИЕ ДАННЫХ ПОЛЬЗОВАТЕЛЯ =====================
app.post('/api/user/data', authMiddleware, async (req, res) => {
    const { menu, exercises, checklist, workout_days } = req.body;
    
    try {
        await pool.query(
            `INSERT INTO user_data (user_id, menu, exercises, checklist, workout_days) 
             VALUES ($1, $2, $3, $4, $5) 
             ON CONFLICT (user_id) DO UPDATE SET 
                menu = EXCLUDED.menu,
                exercises = EXCLUDED.exercises,
                checklist = EXCLUDED.checklist,
                workout_days = EXCLUDED.workout_days,
                updated_at = NOW()`,
            [req.userId, menu, exercises, checklist, workout_days]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Save data error:', err);
        res.status(500).json({ error: 'Ошибка сохранения данных' });
    }
});

// ===================== ПОЛУЧЕНИЕ ПРОФИЛЯ =====================
app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT name, surname, age, weight, subscription, pro_expires_at, created_at FROM users WHERE id = $1',
            [req.userId]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Profile error:', err);
        res.status(500).json({ error: 'Ошибка' });
    }
});

// ===================== ОБНОВЛЕНИЕ ПРОФИЛЯ =====================
app.put('/api/user/profile', authMiddleware, async (req, res) => {
    const { weight, age } = req.body;
    try {
        await pool.query('UPDATE users SET weight = $1, age = $2 WHERE id = $3', [weight, age, req.userId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Update profile error:', err);
        res.status(500).json({ error: 'Ошибка' });
    }
});

// ===================== ОБНОВЛЕНИЕ PRO СТАТУСА (для тестов) =====================
app.post('/api/upgrade-pro', authMiddleware, async (req, res) => {
    const { expires_at } = req.body;
    try {
        await pool.query(
            'UPDATE users SET subscription = $1, pro_expires_at = $2 WHERE id = $3',
            ['pro', expires_at, req.userId]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Upgrade error:', err);
        res.status(500).json({ error: 'Ошибка' });
    }
});

// ===================== ТЕСТОВЫЙ ЭНДПОИНТ =====================
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Fitness backend is running!' });
});

// ===================== ЗАПУСК =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Server is running on port ${PORT}`);
});
