// server.js - Backend Node.js con Express e SQLite
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const axios = require('axios');
const https = require('https');
require('dotenv').config();

const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
//FGT_API_URL="https://192.168.200.254";
//FGT_API_KEY="t0xkx7nHGctH8g74cx9438bppxsbcs";

const {
    FGT_API_URL,
    FGT_API_KEY,
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    JWT_SECRET // La chiave segreta per firmare i token
} = process.env;

if (!FGT_API_KEY || !ADMIN_EMAIL || !ADMIN_PASSWORD || !JWT_SECRET) {
    console.error('ERRORE CRITICO: Una o più variabili d\'ambiente (FGT_..., ADMIN_..., JWT_SECRET) non sono impostate!');
    process.exit(1); // Esce con errore
}

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

function generatePassword(length = 8) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let pwd = '';
  for (let i = 0; i < length; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pwd;
}

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Servi file statici dalla cartella public

// Inizializzazione Database
const DATA_DIR = process.env.DATA_DIR || __dirname;
const dbPath = path.join(DATA_DIR, 'visitors.db');
const db = new sqlite3.Database(dbPath);

// Creazione tabelle se non esistono
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            company TEXT NOT NULL,
            meetingPerson TEXT NOT NULL,
            entryTime DATETIME NOT NULL,
            exitTime DATETIME,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )    
    `);

    // dopo CREATE TABLE IF NOT EXISTS visitors (...)
    db.run(`ALTER TABLE visitors ADD COLUMN fgt_user_id TEXT`, () => {});
    db.run(`ALTER TABLE visitors ADD COLUMN fgt_password TEXT`, () => {});


    // Trigger per aggiornare updated_at
    db.run(`
        CREATE TRIGGER IF NOT EXISTS update_visitors_timestamp 
        AFTER UPDATE ON visitors
        BEGIN
            UPDATE visitors SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
        END
    `);
});

// API Routes
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    // 1. Controlla le credenziali con quelle del file .env
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        
        // 2. Credenziali corrette: crea un token!
        const payload = { user: 'admin', email: email }; // Contenuto del token
        const token = jwt.sign(
            payload, 
            JWT_SECRET, 
            { expiresIn: '24h' } // Il token scade dopo 24 ore
        );

        // 3. Invia il token al frontend
        res.json({ message: "Accesso riuscito!", token: token });

    } else {
        // 4. Credenziali errate
        res.status(401).json({ error: 'Email o password non corretti' });
    }
});

function authenticateToken(req, res, next) {
    // 1. Cerca il token nell'header "Authorization"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ error: 'Accesso negato. Token non fornito.' });
    }

    // 2. Verifica che il token sia valido e non scaduto
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // Se il token è scaduto o non valido
            return res.status(403).json({ error: 'Token non valido o scaduto.' });
        }

        // 3. Il token è valido!
        req.user = user; // Aggiunge i dati dell'utente alla richiesta
        next(); // Prosegui alla rotta richiesta (es. /api/stats)
    });
}

// Verifica se un codice è già registrato
app.get('/api/visitors/check/:code', (req, res) => {
  const code = req.params.code;
  db.get(
    `SELECT 
       id, code, firstName, lastName, company, meetingPerson,
       entryTime, exitTime, status,
       fgt_user_id, fgt_password
     FROM visitors
     WHERE code = ?
     ORDER BY entryTime DESC LIMIT 1`,
    [code],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row) {
        // Metti il campo `exists` e restituisci l’intera riga, compresa fgt_password
        return res.json({ exists: true, visitor: row });
      } else {
        return res.json({ exists: false });
      }
    }
  );
});


// Registra nuovo visitatore
app.post('/api/visitors/register', (req, res) => {
  const { code, firstName, lastName, company, meetingPerson, forceReuse } = req.body;
  const entryTime = new Date().toISOString();

  // 1) Inserimento record visitor
  db.run(
    `INSERT INTO visitors (code, firstName, lastName, company, meetingPerson, entryTime, status)
     VALUES (?, ?, ?, ?, ?, ?, 'active')`,
    [code, firstName, lastName, company, meetingPerson, entryTime],
    function(insertErr) {
      if (insertErr) {
        console.error(insertErr);
        return res.status(500).json({ error: 'Errore del database' });
      }

      // 2) Recupera il visitor appena creato
      db.get(
        'SELECT * FROM visitors WHERE id = ?',
        [this.lastID],
        async (getErr, row) => {
          if (getErr) {
            console.error(getErr);
            return res.status(500).json({ error: 'Errore del database' });
          }

          // --- INIZIO PATCH FortiGate API ---
          const fgtUserId   = `${firstName}.${lastName}`.replace(/\s+/g, '').toLocaleLowerCase();
          const fgtPassword = generatePassword();

          try {
            // 3) Chiamata POST a FortiGate
            await axios.post(
              `${FGT_API_URL}/api/v2/cmdb/user/group/GUEST%20GROUP/guest?vdom=root`,
              {
                'user-id':  fgtUserId,
                'company':    company,
                expiration: 43200,
                password:   fgtPassword
              },
              {
                headers: {
                  'Content-Type':  'application/json',
                  'Authorization': `Bearer ${FGT_API_KEY}`
                },
                httpsAgent
              }
            );

            // 4) Salva le credenziali FortiGate in SQLite
            db.run(
              'UPDATE visitors SET fgt_user_id = ?, fgt_password = ? WHERE id = ?',
              [fgtUserId, fgtPassword, row.id],
              (updateErr) => {
                if (updateErr) console.error('Errore salvataggio FGT su DB:', updateErr);
              }
            );

            // Includi le credenziali nella risposta
            row.fgt_user_id  = fgtUserId;
            row.fgt_password = fgtPassword;

          } catch (fgtErr) {
            console.error('Errore chiamata FortiGate:', fgtErr);
            // A questo punto row non avrà fgt_* ma rispondi comunque
          }
          // --- FINE PATCH FortiGate API ---

          // 5) Rispondi al client con il visitor (e le credenziali, se create)
          return res.status(201).json(row);
        }
      );
    }
  );
});


// Endpoint specifico per riutilizzo codici (fallback)
app.post('/api/visitors/reuse', (req, res) => {
    const { code, firstName, lastName, company, meetingPerson } = req.body;
    
    // Validazione
    if (!code || !firstName || !lastName || !company || !meetingPerson) {
        return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
    }
    
    // Verifica che il codice sia solo numerico
    if (!/^\d+$/.test(code)) {
        return res.status(400).json({ error: 'Il codice deve contenere solo numeri' });
    }
    
    // Controlla se il codice è attualmente attivo
    db.get('SELECT * FROM visitors WHERE code = ? AND status = "active"', [code], (err, activeVisitor) => {
        if (err) {
            console.error('Errore controllo codice attivo:', err);
            return res.status(500).json({ error: 'Errore del database' });
        }
        
        if (activeVisitor) {
            return res.status(409).json({ error: 'Codice già in uso da un visitatore attivo' });
        }
        
        // Il codice è libero, crea nuova registrazione
        const entryTime = new Date().toISOString();
        
        db.run(
            `INSERT INTO visitors (code, firstName, lastName, company, meetingPerson, entryTime, status) 
             VALUES (?, ?, ?, ?, ?, ?, 'active')`,
            [code, firstName, lastName, company, meetingPerson, entryTime],
            function(err) {
                if (err) {
                    console.error('Errore riutilizzo codice:', err);
                    return res.status(500).json({ error: 'Errore del database' });
                }
                
                // Recupera il visitatore appena inserito
                db.get('SELECT * FROM visitors WHERE id = ?', [this.lastID], (err, row) => {
                    if (err) {
                        console.error('Errore recupero visitatore:', err);
                        return res.status(500).json({ error: 'Errore del database' });
                    }
                    
                    console.log(`Codice riutilizzato: ${code} - ${firstName} ${lastName}`);
                    res.status(201).json(row);
                });
            }
        );
    });
});

// Termina visita
app.put('/api/visitors/end/:code', (req, res) => {
    const { code } = req.params;
    const exitTime = new Date().toISOString();
    
    db.run(
        'UPDATE visitors SET exitTime = ?, status = "completed" WHERE code = ? AND status = "active"',
        [exitTime, code],
        function(err) {
            if (err) {
                console.error('Errore terminazione visita:', err);
                return res.status(500).json({ error: 'Errore del database' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Visitatore non trovato o già uscito' });
            }
            
            console.log(`Visita terminata: ${code} - Codice ora disponibile per riutilizzo`);
            res.json({ message: 'Visita terminata con successo' });
        }
    );
});

// Ottieni tutti i visitatori per management
app.get('/api/visitors/all', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM visitors ORDER BY entryTime DESC',
        [],
        (err, rows) => {
            if (err) {
                console.error('Errore recupero visitatori:', err);
                return res.status(500).json({ error: 'Errore del database' });
            }
            
            res.json(rows);
        }
    );
});

// Ottieni visitatore specifico
app.get('/api/visitors/:code', (req, res) => {
    const { code } = req.params;
    
    db.get('SELECT * FROM visitors WHERE code = ?', [code], (err, row) => {
        if (err) {
            console.error('Errore recupero visitatore:', err);
            return res.status(500).json({ error: 'Errore del database' });
        }
        
        if (!row) {
            return res.status(404).json({ error: 'Visitatore non trovato' });
        }
        
        res.json(row);
    });
});

// Forza terminazione visita (management)
app.put('/api/visitors/force-end/:code', authenticateToken, (req, res) => {
    const { code } = req.params;
    const exitTime = new Date().toISOString();
    
    db.run(
        'UPDATE visitors SET exitTime = ?, status = "completed" WHERE code = ? AND status = "active"',
        [exitTime, code],
        function(err) {
            if (err) {
                console.error('Errore terminazione forzata:', err);
                return res.status(500).json({ error: 'Errore del database' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Visitatore non trovato o già terminato' });
            }
            
            console.log(`Visita terminata forzatamente: ${code} - Codice ora disponibile per riutilizzo`);
            res.json({ message: 'Visita terminata forzatamente' });
        }
    );
});

// Esporta dati in CSV
app.get('/api/visitors/export/csv', authenticateToken, (req, res) => {
    db.all('SELECT * FROM visitors ORDER BY entryTime DESC', [], (err, rows) => {
        if (err) {
            console.error('Errore esportazione:', err);
            return res.status(500).json({ error: 'Errore del database' });
        }
        
        let csv = 'ID,Codice,Nome,Cognome,Azienda,Incontra,Entrata,Uscita,Stato,Creato,Aggiornato\n';
        
        rows.forEach(row => {
            const entryTime = new Date(row.entryTime).toLocaleString('it-IT');
            const exitTime = row.exitTime ? new Date(row.exitTime).toLocaleString('it-IT') : '';
            const createdAt = new Date(row.created_at).toLocaleString('it-IT');
            const updatedAt = new Date(row.updated_at).toLocaleString('it-IT');
            
            csv += `${row.id},"${row.code}","${row.firstName}","${row.lastName}","${row.company}","${row.meetingPerson}","${entryTime}","${exitTime}","${row.status}","${createdAt}","${updatedAt}"\n`;
        });
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="visitor_logs_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csv);
    });
});

// Statistiche per dashboard
app.get('/api/stats', authenticateToken, (req, res) => {
    const queries = {
        total: 'SELECT COUNT(*) as count FROM visitors',
        active: 'SELECT COUNT(*) as count FROM visitors WHERE status = "active"',
        today: `SELECT COUNT(*) as count FROM visitors WHERE DATE(entryTime) = DATE('now', 'localtime')`,
        thisWeek: `SELECT COUNT(*) as count FROM visitors WHERE DATE(entryTime) >= DATE('now', '-7 days', 'localtime')`
    };
    
    const stats = {};
    let completed = 0;
    const total = Object.keys(queries).length;
    
    Object.entries(queries).forEach(([key, query]) => {
        db.get(query, [], (err, row) => {
            if (err) {
                console.error(`Errore statistica ${key}:`, err);
                stats[key] = 0;
            } else {
                stats[key] = row.count;
            }
            
            completed++;
            if (completed === total) {
                res.json(stats);
            }
        });
    });
});

// Backup database
app.get('/api/backup', authenticateToken, (req, res) => {
    const backupPath = path.join(DATA_DIR, 'backups');
    
    // Crea cartella backup se non esiste
    if (!fs.existsSync(backupPath)) {
        fs.mkdirSync(backupPath);
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join(backupPath, `visitors_backup_${timestamp}.db`);
    
    fs.copyFile(dbPath, backupFile, (err) => {
        if (err) {
            console.error('Errore backup:', err);
            return res.status(500).json({ error: 'Errore durante il backup' });
        }
        
        console.log(`Backup creato: ${backupFile}`);
        res.json({ message: 'Backup creato con successo', file: backupFile });
    });
});

// Serve l'applicazione frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Gestione errori
app.use((err, req, res, next) => {
    console.error('Errore server:', err);
    res.status(500).json({ error: 'Errore interno del server' });
});

// 404 Handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint non trovato' });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nChiusura server in corso...');
    db.close((err) => {
        if (err) {
            console.error('Errore chiusura database:', err);
        } else {
            console.log('Database chiuso correttamente');
        }
        process.exit(0);
    });
});

// NOTA: Hai definito /api/visitors/all DUE VOLTE. 
// Express userà solo questa seconda definizione. 
// La proteggo per sicurezza, ma dovresti rimuovere la prima.
app.get('/api/visitors/all', authenticateToken, (req, res) => {
    const { firstName, lastName, company } = req.query;
    const cond = [], params = [];
    if (firstName) { cond.push('firstName LIKE ?'); params.push(`%${firstName}%`); }
    if (lastName)  { cond.push('lastName  LIKE ?'); params.push(`%${lastName}%`); }
    if (company)   { cond.push('company   LIKE ?'); params.push(`%${company}%`); }
    let sql = 'SELECT * FROM visitors' + (cond.length ? ' WHERE ' + cond.join(' AND ') : '');
    db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
    });
});

// GET password del visitor filtrato per codice (o nome/cognome/azienda)
app.get('/api/visitors/password', (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'Manca il parametro code' });

  db.get(
    'SELECT fgt_password FROM visitors WHERE code = ? ORDER BY entryTime DESC LIMIT 1',
    [code],
    (err, row) => {
      if (err)    return res.status(500).json({ error: err.message });
      if (!row)   return res.status(404).json({ error: 'Visitatore non trovato' });
      res.json({ password: row.fgt_password });
    }
  );
});

// Avvio server
app.listen(PORT, () => {
    console.log(`🚀 Server avviato su http://localhost:${PORT}`);
    console.log(`📁 Database: ${dbPath}`);
    console.log(`📊 Management: http://localhost:${PORT} (clicca pulsante Management)`);
});

module.exports = app;