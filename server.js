require('dotenv').config(); // Ładuje zmienne środowiskowe z .env
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); // Dodajemy CORS

const app = express();
const port = process.env.PORT || 3000; // Używamy portu z .env lub 3000

// Middleware
app.use(cors()); // Włączamy CORS dla wszystkich żądań
app.use(express.json()); // Umożliwia parsowanie JSON-a z żądań

// Połączenie z bazą danych MongoDB
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/czat_app'; // Domyślna baza lokalna

mongoose.connect(mongoURI)
    .then(() => console.log('Połączono z bazą danych MongoDB'))
    .catch(err => console.error('Błąd połączenia z bazą danych:', err));

// Definicja Schematu i Modelu Mongoose dla Użytkowników
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true } // W prawdziwej aplikacji hasła POWINNY BYĆ HASZOWANE!
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

// ----- Endpointy API -----

// Rejestracja użytkownika (dla uproszczenia bez haszowania hasła)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const newUser = new User({ username, password });
        await newUser.save();
        res.status(201).json({ message: 'Użytkownik zarejestrowany pomyślnie!' });
    } catch (error) {
        if (error.code === 11000) { // Kod błędu dla duplikatu klucza (unikalny username)
            return res.status(409).json({ message: 'Nazwa użytkownika już istnieje.' });
        }
        res.status(500).json({ message: 'Błąd rejestracji.', error: error.message });
    }
});

// Logowanie użytkownika (dla uproszczenia)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username, password }); // W prawdziwej apce porównanie haszowanego hasła
        if (!user) {
            return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }
        // W prawdziwej aplikacji tutaj zwracalibyśmy token JWT dla autoryzacji
        res.status(200).json({ message: 'Zalogowano pomyślnie!', userId: user._id, username: user.username });
    } catch (error) {
        res.status(500).json({ message: 'Błąd logowania.', error: error.message });
    }
});

// Wysyłanie wiadomości
app.post('/send-message', async (req, res) => {
    const { senderId, receiverUsername, content } = req.body;
    try {
        const receiver = await User.findOne({ username: receiverUsername });
        if (!receiver) {
            return res.status(404).json({ message: 'Odbiorca nie istnieje.' });
        }
        const newMessage = new Message({
            sender: senderId,
            receiver: receiver._id,
            content
        });
        await newMessage.save();
        res.status(201).json({ message: 'Wiadomość wysłana pomyślnie!' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd wysyłania wiadomości.', error: error.message });
    }
});

// Pobieranie odebranych wiadomości dla danego użytkownika
app.get('/messages/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        // Pobierz wiadomości, gdzie 'receiver' to dany userId
        // Użyj populate('sender', 'username') aby pobrać nazwę użytkownika nadawcy
        const messages = await Message.find({ receiver: userId })
                                       .populate('sender', 'username') // Pobiera tylko pole 'username' z obiektu User
                                       .sort({ timestamp: -1 }); // Sortuj od najnowszych
        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wiadomości.', error: error.message });
    }
});

// Pobieranie wszystkich użytkowników (do wyboru odbiorcy)
app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username'); // Pobierz tylko nazwę użytkownika
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania użytkowników.', error: error.message });
    }
});


// Start serwera
app.listen(port, () => {
    console.log(`Serwer działa na http://localhost:${port}`);
});