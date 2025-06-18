require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const webPush = require('web-push');
const bcrypt = require('bcryptjs'); // ZMIANA: Dodajemy bcryptjs do haszowania haseł
const jwt = require('jsonwebtoken'); // ZMIANA: Dodajemy jsonwebtoken do autoryzacji

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// ZMIANA: Sekretny klucz JWT - BARDZO WAŻNE: Wygeneruj to i przechowuj w .env!
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
    console.error('Brak JWT_SECRET w zmiennych środowiskowych! Aplikacja nie będzie bezpieczna.');
    console.error('Wygeneruj losowy, długi ciąg znaków i dodaj do .env jako JWT_SECRET.');
    process.exit(1); // Zakończ aplikację, jeśli brak klucza (dla środowiska produkcyjnego)
}

// Połączenie z bazą danych MongoDB
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/czat_app';

mongoose.connect(mongoURI)
    .then(() => console.log('Połączono z bazą danych MongoDB'))
    .catch(err => console.error('Błąd połączenia z bazą danych:', err));

// Definicja Schematu i Modelu Mongoose dla Użytkowników
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // ZMIANA: Hasło będzie haszowane
    pushSubscription: { type: Object }
});
const User = mongoose.model('User', userSchema);

// Definicja Schematu i Modelu Mongoose dla Wiadomości
const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// ----- Konfiguracja Web Push -----
const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const privateVapidKey = process.env.VAPID_PRIVATE_KEY;

if (!publicVapidKey || !privateVapidKey) {
    console.error('Brak kluczy VAPID w zmiennych środowiskowych! Powiadomienia push nie będą działać.');
    console.error('Wygeneruj je raz: npx web-push generate-vapid-keys');
} else {
    webPush.setVapidDetails(
        'mailto:twojemail@example.com', // Zastąp swoim adresem email
        publicVapidKey,
        privateVapidKey
    );
    console.log('Klucze VAPID skonfigurowane.');
}

// NOWOŚĆ: Middleware do weryfikacji tokenów JWT
const authenticateToken = (req, res, next) => {
    // Pobierz token z nagłówka Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'Brak tokenu autoryzacyjnego.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.error('Błąd weryfikacji tokenu:', err.message);
            // Zwróć 403 Forbidden, jeśli token jest nieprawidłowy (np. wygasł)
            return res.status(403).json({ message: 'Nieprawidłowy lub wygasły token autoryzacyjny.' });
        }
        req.user = user; // Dodaj payload tokenu do obiektu żądania
        next(); // Przejdź do następnego middleware/endpointu
    });
};

// ----- Endpointy API -----

// Rejestracja użytkownika (ZMIANA: Haszowanie hasła)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        // ZMIANA: Haszowanie hasła przed zapisaniem
        const salt = await bcrypt.genSalt(10); // Generuj "sól"
        const hashedPassword = await bcrypt.hash(password, salt); // Haszuj hasło z solą

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'Użytkownik zarejestrowany pomyślnie!' });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ message: 'Nazwa użytkownika już istnieje.' });
        }
        res.status(500).json({ message: 'Błąd rejestracji.', error: error.message });
    }
});

// Logowanie użytkownika (ZMIANA: Porównywanie haszowanego hasła i generowanie JWT)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }

        // ZMIANA: Porównanie haszowanego hasła
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }

        // ZMIANA: Generowanie tokenu JWT
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            jwtSecret,
            { expiresIn: '1h' } // Token wygaśnie po 1 godzinie (dla sesji)
        );

        res.status(200).json({
            message: 'Zalogowano pomyślnie!',
            token: token, // Zwracamy token
            userId: user._id, // Opcjonalnie, do użycia w frontendzie (np. dla localStorage)
            username: user.username // Opcjonalnie
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd logowania.', error: error.message });
    }
});

// Wysyłanie wiadomości (ZMIANA: Chronimy endpoint za pomocą authenticateToken)
// Teraz tylko zalogowani użytkownicy z ważnym tokenem mogą wysyłać wiadomości
app.post('/send-message', authenticateToken, async (req, res) => { // ZMIANA
    // req.user zawiera teraz payload z tokenu (userId i username)
    const senderId = req.user.userId; // ZMIANA: Pobieramy senderId z tokenu
    const { receiverUsername, content } = req.body;

    try {
        const receiver = await User.findOne({ username: receiverUsername });
        if (!receiver) {
            return res.status(404).json({ message: 'Odbiorca nie istnieje.' });
        }
        const sender = await User.findById(senderId); // Pobierz nadawcę dla nazwy w powiadomieniu
        if (!sender) {
            // To nie powinno się zdarzyć, jeśli token jest prawidłowy i użytkownik istnieje
            return res.status(404).json({ message: 'Nadawca nie istnieje lub błąd autoryzacji.' });
        }

        const newMessage = new Message({
            sender: senderId,
            receiver: receiver._id,
            content
        });
        await newMessage.save();

        if (receiver.pushSubscription) {
            const payload = JSON.stringify({
                title: `Nowa wiadomość od ${sender.username}!`,
                body: content,
                icon: '/icon.png',
                data: { url: process.env.FRONTEND_URL || 'http://localhost:8080' }
            });
            try {
                await webPush.sendNotification(receiver.pushSubscription, payload);
                console.log('Powiadomienie push wysłane do', receiver.username);
            } catch (pushError) {
                console.error('Błąd wysyłania powiadomienia push:', pushError);
                if (pushError.statusCode === 410) {
                    receiver.pushSubscription = undefined;
                    await receiver.save();
                    console.log('Usunięto nieaktualną subskrypcję dla', receiver.username);
                }
            }
        }

        res.status(201).json({ message: 'Wiadomość wysłana pomyślnie!' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd wysyłania wiadomości.', error: error.message });
    }
});

// Pobieranie odebranych wiadomości (ZMIANA: Chronimy endpoint)
// Użytkownik może pobrać tylko SWOJE wiadomości
app.get('/messages/:userId', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const since = req.query.since ? parseInt(req.query.since) : 0; // Ta zmienna nie jest już używana w nowym fetchMessages, ale nie przeszkadza

    try {
        let query = {
            $or: [ // Pobieramy wiadomości, gdzie użytkownik jest odbiorcą LUB nadawcą
                { receiver: userId },
                { sender: userId }
            ]
        };
        // Jeśli będziesz chciał filtrować po czasie, możesz to dodać z powrotem.
        // if (since > 0) {
        //     query.timestamp = { $gt: new Date(since) };
        // }

        // ZMIANA: Pobieramy username i _id nadawcy (i odbiorcy, jeśli chcesz)
        const messages = await Message.find(query)
                                       .populate('sender', 'username _id') // ZMIANA: Dodajemy '_id'
                                       .populate('receiver', 'username _id') // Opcjonalnie: pobierz odbiorcę
                                       .sort({ timestamp: 1 }); // Sortuj od najstarszych do najnowszych

        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wiadomości.', error: error.message });
    }
});

// Pobieranie wszystkich użytkowników (ZMIANA: Chronimy endpoint)
app.get('/users', authenticateToken, async (req, res) => { // ZMIANA
    try {
        // Nadal pobieramy wszystkich użytkowników do wyboru odbiorcy, ale tylko dla zalogowanych
        const users = await User.find({}, 'username');
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania użytkowników.', error: error.message });
    }
});

// Endpoint do odbierania subskrypcji powiadomień push z frontendu (ZMIANA: Chronimy endpoint)
app.post('/subscribe-push', authenticateToken, async (req, res) => { // ZMIANA
    const subscription = req.body.subscription;
    const userId = req.user.userId; // ZMIANA: Pobieramy userId z tokenu

    if (!subscription || !userId) {
        return res.status(400).json({ message: 'Brak danych subskrypcji lub ID użytkownika.' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
        }

        user.pushSubscription = subscription;
        await user.save();

        res.status(200).json({ message: 'Subskrypcja push zapisana pomyślnie.' });
    } catch (error) {
        console.error('Błąd zapisywania subskrypcji push:', error);
        res.status(500).json({ message: 'Błąd zapisywania subskrypcji push.' });
    }
});

// Endpoint do pobierania klucza publicznego VAPID dla frontendu (BEZ ZMIAN: nie wymaga autoryzacji)
app.get('/vapidPublicKey', (req, res) => {
    res.status(200).json({ publicKey: publicVapidKey });
});


// Start serwera
app.listen(port, () => {
    console.log(`Serwer działa na http://localhost:${port}`);
});