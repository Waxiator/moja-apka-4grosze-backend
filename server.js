require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const webPush = require('web-push'); // NOWOŚĆ: dodajemy web-push

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Połączenie z bazą danych MongoDB
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/czat_app';

mongoose.connect(mongoURI)
    .then(() => console.log('Połączono z bazą danych MongoDB'))
    .catch(err => console.error('Błąd połączenia z bazą danych:', err));

// Definicja Schematu i Modelu Mongoose dla Użytkowników
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // NOWOŚĆ: Dodajemy pole do przechowywania subskrypcji powiadomień push
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

// ----- Konfiguracja Web Push (NOWOŚĆ) -----
// WAŻNE: Wygeneruj własne VAPID keys! Możesz to zrobić raz, np. przez `npx web-push generate-vapid-keys` w terminalu.
// Następnie dodaj je do pliku .env i nie udostępniaj nikomu!
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


// ----- Endpointy API -----

// Rejestracja użytkownika (bez zmian)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const newUser = new User({ username, password });
        await newUser.save();
        res.status(201).json({ message: 'Użytkownik zarejestrowany pomyślnie!' });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ message: 'Nazwa użytkownika już istnieje.' });
        }
        res.status(500).json({ message: 'Błąd rejestracji.', error: error.message });
    }
});

// Logowanie użytkownika (bez zmian)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username, password });
        if (!user) {
            return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }
        res.status(200).json({ message: 'Zalogowano pomyślnie!', userId: user._id, username: user.username });
    } catch (error) {
        res.status(500).json({ message: 'Błąd logowania.', error: error.message });
    }
});

// Wysyłanie wiadomości (ZMODYFIKOWANE: dodajemy wysyłanie powiadomień push)
app.post('/send-message', async (req, res) => {
    const { senderId, receiverUsername, content } = req.body;
    try {
        const receiver = await User.findOne({ username: receiverUsername });
        if (!receiver) {
            return res.status(404).json({ message: 'Odbiorca nie istnieje.' });
        }
        const sender = await User.findById(senderId); // Pobierz nadawcę dla nazwy w powiadomieniu
        if (!sender) {
            return res.status(404).json({ message: 'Nadawca nie istnieje.' });
        }

        const newMessage = new Message({
            sender: senderId,
            receiver: receiver._id,
            content
        });
        await newMessage.save();

        // NOWOŚĆ: Wyślij powiadomienie push do odbiorcy, jeśli ma subskrypcję
        if (receiver.pushSubscription) {
            const payload = JSON.stringify({
                title: `Nowa wiadomość od ${sender.username}!`,
                body: content,
                icon: '/icon.png', // Ikona powiadomienia (musi być dostępna publicznie)
                data: { url: process.env.FRONTEND_URL || 'http://localhost:8080' } // URL do otwarcia po kliknięciu
            });
            try {
                await webPush.sendNotification(receiver.pushSubscription, payload);
                console.log('Powiadomienie push wysłane do', receiver.username);
            } catch (pushError) {
                console.error('Błąd wysyłania powiadomienia push:', pushError);
                // Usuń nieaktualną subskrypcję, jeśli wystąpi błąd (np. użytkownik ją usunął)
                if (pushError.statusCode === 410) { // GONE status
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

// Pobieranie odebranych wiadomości (bez zmian)
app.get('/messages/:userId', async (req, res) => {
    const { userId } = req.params;
    const since = req.query.since ? parseInt(req.query.since) : 0;

    try {
        let query = { receiver: userId };
        if (since > 0) {
            query.timestamp = { $gt: new Date(since) };
        }

        const messages = await Message.find(query)
                                       .populate('sender', 'username')
                                       .sort({ timestamp: 1 });

        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wiadomości.', error: error.message });
    }
});

// Pobieranie wszystkich użytkowników (bez zmian)
app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username');
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania użytkowników.', error: error.message });
    }
});

// NOWOŚĆ: Endpoint do odbierania subskrypcji powiadomień push z frontendu
app.post('/subscribe-push', async (req, res) => {
    const subscription = req.body.subscription;
    const userId = req.body.userId;

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

// NOWOŚĆ: Endpoint do pobierania klucza publicznego VAPID dla frontendu
app.get('/vapidPublicKey', (req, res) => {
    res.status(200).json({ publicKey: publicVapidKey });
});


// Start serwera
app.listen(port, () => {
    console.log(`Serwer działa na http://localhost:${port}`);
});