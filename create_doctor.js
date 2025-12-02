const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const db = new sqlite3.Database("./database.db");

// Change these values to the doctor you want to create:
const username = "doctor2";
const password = "doctor2";
const name = "Dr. Kotthru";
const birthday = "2003-10-04";

async function createDoctor() {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users (username, password, role, name, birthday)
         VALUES (?, ?, 'doctor', ?, ?)`,
        [username, hashedPassword, name, birthday],
        function (err) {
            if (err) {
                console.error("Error inserting doctor:", err);
            } else {
                console.log("Doctor created successfully with ID:", this.lastID);
            }
            db.close();
        }
    );
}

createDoctor();
