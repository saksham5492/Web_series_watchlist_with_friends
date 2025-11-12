// merged app.js
const express = require("express");
const session = require("express-session");
const path = require("path");
const ejsMate = require("ejs-mate");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const wrapAsync = require("./utils/wrapAsync.js");
const ExpressError = require("./utils/expressError.js");
const nodemailer = require("nodemailer");
dotenv.config();

// Initialize app
const app = express();

// Session setup
app.use(
	session({
		secret: "yourSecretKeyHere",
		resave: false,
		saveUninitialized: false,
		cookie: { secure: false }, // set true only if using HTTPS
	})
);

// View engine & middlewares
app.engine("ejs", ejsMate);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// MySQL Connection (using the latest password provided in your files)
const connection = mysql.createConnection({
	host: "localhost",
	user: "root",
	database: "watchlist",
	password: "Tejaswi49!",
	multipleStatements: true,
});

connection.connect((err) => {
	if (err) {
		console.error("❌ Database connection failed:", err);
	} else {
		console.log("✅ Connected to MySQL database.");
	}
});

// Make logged-in user available in all EJS templates
app.use((req, res, next) => {
	res.locals.user = req.session.user || null;
	next();
});

// Middleware: load all genres for nav dropdown (available in all EJS)
app.use(async (req, res, next) => {
	try {
		const [allGenres] = await connection
			.promise()
			.query(`SELECT genre_id, genre_name FROM genres ORDER BY genre_name;`);
		res.locals.allGenres = allGenres;
	} catch (err) {
		console.error("Error loading genres:", err);
		res.locals.allGenres = [];
	}
	next();
});

// ---------------------------------------------------------
// ROUTES
// ---------------------------------------------------------

// Root
app.get("/", (req, res) => {
	res.send("Server running fine!");
});

// Login page (GET)
app.get(
	"/watchlist/login",
	wrapAsync(async (req, res) => {
		const message =
			req.query.verified === "success"
				? "✅ Verification successful! Please log in."
				: null;
		res.render("pages/login", { title: "Login", message });
	})
);

// Register page (GET)
app.get(
	"/watchlist/register",
	wrapAsync(async (req, res) => {
		res.render("pages/register", { title: "Register" });
	})
);

// REGISTER (POST) with OTP
app.post(
	"/watchlist/register",
	wrapAsync(async (req, res) => {
		const { name, email, password } = req.body;

		if (!name || !email || !password) {
			return res.status(400).send("All fields are required.");
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

		const q = `
      INSERT INTO user (name, email, password, verified, otp, otp_expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        otp = VALUES(otp),
        otp_expires_at = VALUES(otp_expires_at),
        verified = 0,
        password = VALUES(password)
    `;

		connection.query(
			q,
			[name, email, hashedPassword, 0, otp, otpExpiry],
			async (err) => {
				if (err) {
					console.error("Error inserting user:", err);
					return res.status(500).send("Registration failed.");
				}

				try {
					const transporter = nodemailer.createTransport({
						service: "gmail",
						auth: {
							user: process.env.EMAIL,
							pass: process.env.EMAIL_PASS,
						},
					});

					await transporter.sendMail({
						from: process.env.EMAIL,
						to: email,
						subject: "Your OTP for Email Verification",
						html: `<p>Hi ${name},</p>
                   <p>Your OTP is: <b>${otp}</b></p>
                   <p>This code will expire in 10 minutes.</p>`,
					});

					console.log(`✅ OTP sent to ${email}`);
					res.redirect(`/verify-otp?email=${encodeURIComponent(email)}`);
				} catch (mailErr) {
					console.error("Email sending failed:", mailErr);
					res.status(500).send("Error sending OTP email.");
				}
			}
		);
	})
);

// LOGIN (POST)
app.post(
	"/watchlist/login",
	wrapAsync(async (req, res) => {
		const { email, password } = req.body;

		if (!email || !password) {
			return res.render("pages/login", {
				title: "Login",
				message: "⚠️ Please fill in all fields.",
			});
		}

		const q = "SELECT * FROM user WHERE email = ?";
		connection.query(q, [email], async (err, results) => {
			if (err) {
				console.error("Database error:", err);
				return res.render("pages/login", {
					title: "Login",
					message: "⚠️ Server error. Try again later.",
				});
			}

			if (results.length === 0) {
				return res.render("pages/login", {
					title: "Login",
					message: "❌ No account found with this email.",
				});
			}

			const user = results[0];

			if (!user.verified) {
				return res.render("pages/login", {
					title: "Login",
					message: "⚠️ Please verify your email before logging in.",
				});
			}

			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return res.render("pages/login", {
					title: "Login",
					message: "❌ Incorrect password.",
				});
			}

			// Store user session
			req.session.user = { id: user.id, name: user.name, email: user.email };

			// Add login success message to session
			req.session.message = `🎉 Welcome back, ${user.name}!`;

			console.log(`✅ ${user.name} logged in successfully.`);
			res.redirect("/watchlist/home");
		});
	})
);

// VERIFY OTP (GET)
app.get("/verify-otp", (req, res) => {
	const { email } = req.query;
	res.render("pages/verify-otp", { title: "Verify OTP", email });
});

// VERIFY OTP (POST)
app.post(
	"/verify-otp",
	wrapAsync(async (req, res) => {
		const { email, otp } = req.body;

		const q = "SELECT * FROM user WHERE email = ? AND otp = ?";
		connection.query(q, [email, otp], (err, results) => {
			if (err) return res.status(500).send("Server error");
			if (results.length === 0) return res.status(400).send("Invalid OTP");

			const user = results[0];
			const now = new Date();

			if (new Date(user.otp_expires_at) < now) {
				return res.status(400).send("OTP expired. Please register again.");
			}

			const updateQ =
				"UPDATE user SET verified = 1, otp = NULL, otp_expires_at = NULL WHERE email = ?";
			connection.query(updateQ, [email], (err2) => {
				if (err2) return res.status(500).send("Error updating user status");
				res.redirect("/watchlist/login?verified=success");
			});
		});
	})
);

// LOGOUT
app.get("/logout", (req, res) => {
	req.session.destroy((err) => {
		if (err) {
			console.error("Logout error:", err);
			return res.redirect("/watchlist/home");
		}
		res.clearCookie("connect.sid");
		res.redirect("/watchlist/login");
	});
});

// HOME PAGE (merged rich implementation)
app.get("/watchlist/home", async (req, res) => {
	try {
		if (!req.session.user) {
			return res.redirect("/watchlist/login");
		}

		// HERO SECTION – Top 6 rated series
		const [heroSeries] = await connection.promise().query(`
      SELECT s.series_id, s.title, s.landscape_poster_url,
             s.series_rating, s.summary AS description
      FROM series s
      ORDER BY s.series_rating DESC
      LIMIT 6;
    `);

		// TRENDING MOVIES – handpicked
		const [trendingMovies] = await connection.promise().query(`
      SELECT series_id, title, poster_url, series_rating, summary AS description
      FROM series
      WHERE title IN (
        'Asur','Family Man','Stranger Things','Panchayat',
        'Rocket Boys','Loki','Kota Factory','Patal Lok',
        'The Boys','Sherlock','The Last of Us','Game of Thrones'
      )
      ORDER BY FIELD(title,
        'Asur','Family Man','Stranger Things','Panchayat',
        'Rocket Boys','Loki','Kota Factory','Patal Lok',
        'The Boys','Sherlock','The Last of Us','Game of Thrones'
      );
    `);

		// Fetch selected genres for home (5/6 you requested)
		const [genres] = await connection.promise().query(`
      SELECT g.genre_id, g.genre_name
      FROM genres g
      WHERE g.genre_name IN ('action','comedy','thriller','crime','sci-fi')
      ORDER BY g.genre_name;
    `);

		// Fetch series for each selected genre (max 8 per genre)
		const genreSeriesPromises = genres.map(async (genre) => {
			const [series] = await connection.promise().query(
				`
        SELECT s.series_id, s.title, s.poster_url, s.series_rating
        FROM series s
        JOIN series_genres sg ON s.series_id = sg.series_id
        WHERE sg.genre_id = ?
        ORDER BY s.series_rating DESC
        LIMIT 8;
        `,
				[genre.genre_id]
			);
			return { genre: genre.genre_name, series };
		});

		const genreSeriesRows = await Promise.all(genreSeriesPromises);

		res.render("pages/home", {
			heroSeries,
			trendingMovies,
			genreSeriesRows,
			user: req.session.user,
			message: req.session.message || null,
		});

		// clear message after rendering
		req.session.message = null;
	} catch (err) {
		console.error("❌ Error loading home:", err);
		res.status(500).send("Internal Server Error");
	}
});

// GENRE PAGE (by id)
app.get("/watchlist/genre/:id", async (req, res) => {
	try {
		const genreId = req.params.id;

		// Get genre name
		const [genreRows] = await connection
			.promise()
			.query(`SELECT genre_name FROM genres WHERE genre_id = ?`, [genreId]);

		if (genreRows.length === 0) return res.status(404).send("Genre not found");
		const genreName = genreRows[0].genre_name;

		// Fetch all series for this genre
		const [seriesList] = await connection.promise().query(
			`
      SELECT 
        s.series_id, 
        s.title, 
        s.poster_url, 
        s.series_rating, 
        s.summary
      FROM series s
      JOIN series_genres sg ON s.series_id = sg.series_id
      WHERE sg.genre_id = ?
      ORDER BY s.series_rating DESC;
    `,
			[genreId]
		);

		res.render("pages/genre", {
			genreName,
			seriesList,
			user: req.session.user || null,
		});
	} catch (err) {
		console.error("❌ Error loading genre page:", err);
		res.status(500).send("Internal Server Error");
	}
});

// SERIES DETAIL (merged full implementation with seasons & episodes)
app.get("/watchlist/series/:id", (req, res) => {
	const seriesId = req.params.id;

	const seriesQuery = `
    SELECT s.series_id, s.title, s.release_year, s.summary, s.platform,
           s.poster_url, s.series_rating, s.trailer_url, g.genre_name ,s.landscape_poster_url
    FROM series s
    JOIN series_genres sg ON s.series_id = sg.series_id
    JOIN genres g ON sg.genre_id = g.genre_id
    WHERE s.series_id = ?
  `;

	const seasonsQuery = `
    SELECT se.season_id, se.number AS season_number, se.title AS season_title,
           se.overview AS season_overview, se.poster_url AS season_poster
    FROM seasons se
    WHERE se.series_id = ?
    ORDER BY se.number
  `;

	const episodesQuery = `
    SELECT e.episode_id, e.season_id, e.number AS episode_number, e.title AS episode_title,
           e.overview AS episode_overview, e.air_date
    FROM episodes e
    JOIN seasons s ON e.season_id = s.season_id
    WHERE s.series_id = ?
    ORDER BY e.season_id, e.number
  `;

	const recommendedQuery = `
    SELECT s.series_id AS id, s.title, s.poster_url, s.series_rating,
           GROUP_CONCAT(g.genre_name SEPARATOR ', ') AS genre_name
    FROM series s
    JOIN series_genres sg ON s.series_id = sg.series_id
    JOIN genres g ON sg.genre_id = g.genre_id
    WHERE s.series_id != ?
    GROUP BY s.series_id
    ORDER BY RAND() LIMIT 6;
  `;

	connection.query(seriesQuery, [seriesId], (err, seriesResult) => {
		if (err || seriesResult.length === 0) {
			console.error(err);
			return res.status(404).send("Series not found");
		}
		const series = seriesResult[0];

		connection.query(seasonsQuery, [seriesId], (err2, seasonsResult) => {
			if (err2) {
				console.error(err2);
				return res.status(500).send("Error fetching seasons");
			}
			const seasons = (seasonsResult || []).map((season) => ({
				season_id: season.season_id,
				number: season.season_number,
				title: season.season_title,
				overview: season.season_overview,
				poster_url: season.season_poster,
				episodes: [],
			}));

			connection.query(episodesQuery, [seriesId], (err3, episodesResult) => {
				if (err3) {
					console.error(err3);
					return res.status(500).send("Error fetching episodes");
				}
				(episodesResult || []).forEach((ep) => {
					const season = seasons.find((s) => s.season_id === ep.season_id);
					if (season) season.episodes.push(ep);
				});

				connection.query(recommendedQuery, [seriesId], (err4, recommended) => {
					if (err4) {
						console.error(err4);
						return res.status(500).send("Error fetching recommendations");
					}

					series.seasons = seasons;
					res.render("pages/series", {
						series,
						recommended,
						user: req.session.user || null,
					});
				});
			});
		});
	});
});

// ===================== PROFILE PAGE =====================
// ===================== PROFILE PAGE =====================
app.get("/watchlist/profile", async (req, res) => {
	try {
		const user = req.session?.user;
		if (!user) {
			return res.redirect("/watchlist/login");
		}

		// Fetch user details
		const [userRows] = await connection
			.promise()
			.query(
				"SELECT id, name, email  FROM user WHERE id = ?",
				[user.id]
			);
		const userData = userRows[0] || user;

		// Fetch friends (both sender and receiver where status = 'accepted')
		const [friends] = await connection.promise().query(
			`
			SELECT u.id, u.name 
			FROM friendships f
			JOIN user u 
				ON (u.id = f.sender_id OR u.id = f.receiver_id)
			WHERE (f.sender_id = ? OR f.receiver_id = ?)
			  AND f.status = 'accepted'
			  AND u.id != ?
			`,
			[user.id, user.id, user.id]
		);

		// Fetch watchlist count
		const [countRows] = await connection
			.promise()
			.query(
				"SELECT COUNT(*) AS count FROM watchlist WHERE user_id = ?",
				[user.id]
			);
		const watchlistCount = countRows[0]?.count || 0;

		// Render profile page
		res.render("pages/profile", {
			user: userData,
			friends,
			watchlistCount,
		});
	} catch (err) {
		console.error("❌ Error rendering profile:", err);
		res.status(500).send("Server Error");
	}
});




// LIVE search results API (for dropdown)
app.get("/api/search", (req, res) => {
	const query = req.query.q;
	if (!query || query.trim() === "") return res.json([]);

	const sql = `
    SELECT 
      s.series_id,
      s.title,
      s.poster_url,
      s.series_rating,
      GROUP_CONCAT(DISTINCT g.genre_name SEPARATOR ', ') AS genre_name
    FROM series s
    JOIN series_genres sg ON s.series_id = sg.series_id
    JOIN genres g ON sg.genre_id = g.genre_id
    WHERE s.title LIKE ?
    GROUP BY s.series_id, s.title, s.poster_url, s.series_rating
    ORDER BY s.series_rating DESC, s.title ASC
    LIMIT 8;
  `;

	connection.query(sql, [`%${query}%`], (err, results) => {
		if (err) {
			console.error(err);
			return res.status(500).json({ error: "Database error" });
		}
		res.json(results);
	});
});

// FULL search page (when user presses SEARCH)
app.get("/watchlist/search", (req, res) => {
	const query = req.query.q;
	if (!query || query.trim() === "") {
		return res.render("pages/search", { results: [], query: "" });
	}

	const sql = `
    SELECT 
      s.series_id, 
      s.title, 
      s.poster_url, 
      s.series_rating, 
      s.summary,
      GROUP_CONCAT(g.genre_name SEPARATOR ', ') AS genre_name
    FROM series s
    JOIN series_genres sg ON s.series_id = sg.series_id
    JOIN genres g ON sg.genre_id = g.genre_id
    WHERE s.title LIKE ?
    GROUP BY s.series_id
    ORDER BY s.series_rating DESC;
  `;

	connection.query(sql, [`%${query}%`], (err, results) => {
		if (err) {
			console.error(err);
			return res.status(500).send("Database error");
		}
		res.render("pages/search", { results, query });
	});
});

// Add to Watchlist
app.post("/watchlist/add", (req, res) => {
	if (!req.session.user)
		return res
			.status(401)
			.json({ success: false, message: "⚠️ Please log in first." });

	const { series_id } = req.body;
	const user_id = req.session.user.id;

	const q = `
    INSERT INTO watchlist (user_id, series_id)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE added_at = NOW();
  `;

	connection.query(q, [user_id, series_id], (err) => {
		if (err) {
			console.error("❌ SQL Error adding to watchlist:", err);
			return res.status(500).json({
				success: false,
				message: "❌ Server error adding to watchlist.",
			});
		}
		console.log("✅ Added to watchlist!");
		return res.json({ success: true, message: "✅ Added to Watchlist!" });
	});
});

// View Watchlist (user's own)
app.get("/watchlist", (req, res) => {
	if (!req.session.user) return res.redirect("/watchlist/login");
	const userId = req.session.user.id;

	const query = `
    SELECT 
      s.series_id, s.title, s.poster_url, s.summary, 
      s.series_rating, s.platform,
      GROUP_CONCAT(g.genre_name SEPARATOR ', ') AS genre_name
    FROM watchlist w
    JOIN series s ON w.series_id = s.series_id
    LEFT JOIN series_genres sg ON s.series_id = sg.series_id
    LEFT JOIN genres g ON sg.genre_id = g.genre_id
    WHERE w.user_id = ?
    GROUP BY s.series_id
    ORDER BY w.added_at DESC;
  `;

	connection.query(query, [userId], (err, results) => {
		if (err) {
			console.error("❌ Error fetching watchlist:", err);
			return res.status(500).send("Server Error");
		}
		res.render("pages/watchlist", {
			watchlist: results,
			user: req.session.user,
		});
	});
});

// Remove from Watchlist
app.delete("/watchlist/delete/:seriesId", (req, res) => {
	if (!req.session.user)
		return res.status(401).json({ message: "Unauthorized" });

	const { seriesId } = req.params;
	const userId = req.session.user.id;

	const q = `DELETE FROM watchlist WHERE user_id = ? AND series_id = ?`;

	connection.query(q, [userId, seriesId], (err, result) => {
		if (err) {
			console.error("❌ Error deleting from watchlist:", err);
			return res.status(500).json({ message: "Error removing series" });
		}

		if (result.affectedRows === 0)
			return res.status(404).json({ message: "Series not found in watchlist" });

		res.json({ message: "✅ Series removed from your watchlist!" });
	});
});

// -------------------- Friendship System --------------------

// View all users (to send friend requests)
app.get("/watchlist/friends", (req, res) => {
	if (!req.session.user) return res.redirect("/watchlist/login");
	const currentUserId = req.session.user.id;

	const q = `
    SELECT id, name, email
    FROM user
    WHERE id != ?
    ORDER BY name ASC
  `;
	connection.query(q, [currentUserId], (err, users) => {
		if (err) {
			console.error("❌ Error fetching users:", err);
			return res.status(500).send("Server error");
		}
		res.render("pages/friends", { users, user: req.session.user });
	});
});

// Send a friend request
app.post("/watchlist/friends/request", (req, res) => {
	if (!req.session.user)
		return res.status(401).json({ message: "Unauthorized" });
	const sender_id = req.session.user.id;
	const { receiver_id } = req.body;

	const q = `
    INSERT INTO friendships (sender_id, receiver_id, status)
    VALUES (?, ?, 'pending')
    ON DUPLICATE KEY UPDATE status = 'pending'
  `;
	connection.query(q, [sender_id, receiver_id], (err) => {
		if (err) {
			console.error("❌ Error sending friend request:", err);
			return res.status(500).json({ message: "Error sending friend request" });
		}
		res.json({ message: "✅ Friend request sent!" });
	});
});

// Accept a friend request
app.post("/watchlist/friends/accept", (req, res) => {
	if (!req.session.user)
		return res.status(401).json({ message: "Unauthorized" });
	const receiver_id = req.session.user.id;
	const { sender_id } = req.body;

	const q = `UPDATE friendships SET status = 'accepted' WHERE sender_id = ? AND receiver_id = ?`;
	connection.query(q, [sender_id, receiver_id], (err) => {
		if (err) {
			console.error("❌ Error accepting friend request:", err);
			return res.status(500).json({ message: "Server error" });
		}
		res.json({ message: "✅ Friend request accepted!" });
	});
});

// View accepted friends
app.get("/watchlist/friends/list", (req, res) => {
	if (!req.session.user) return res.redirect("/watchlist/login");
	const currentUserId = req.session.user.id;

	const q = `
    SELECT u.id, u.name, u.email
    FROM friendships f
    JOIN user u ON (u.id = f.sender_id OR u.id = f.receiver_id)
    WHERE (f.sender_id = ? OR f.receiver_id = ?)
      AND f.status = 'accepted'
      AND u.id != ?
  `;
	connection.query(
		q,
		[currentUserId, currentUserId, currentUserId],
		(err, friends) => {
			if (err) {
				console.error("❌ Error fetching friends list:", err);
				return res.status(500).send("Error fetching friends");
			}
			res.render("pages/friends-list", { friends, user: req.session.user });
		}
	);
});

// View a friend's watchlist
app.get("/watchlist/friends/watchlist/:friendId", (req, res) => {
	if (!req.session.user) return res.redirect("/watchlist/login");

	const userId = req.session.user.id;
	const friendId = req.params.friendId;

	// check friendship
	const checkQ = `
    SELECT * FROM friendships 
    WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
    AND status = 'accepted'
  `;

	connection.query(
		checkQ,
		[userId, friendId, friendId, userId],
		(err, friendsRes) => {
			if (err) {
				console.error("❌ Error verifying friendship:", err);
				return res.status(500).send("Server Error");
			}
			if (friendsRes.length === 0) {
				return res.status(403).send("⚠️ You are not friends with this user.");
			}

			// fetch friend's watchlist
			const q = `
      SELECT s.series_id, s.title, s.poster_url, s.summary, 
             s.series_rating, s.platform,
             GROUP_CONCAT(g.genre_name SEPARATOR ', ') AS genre_name
      FROM watchlist w
      JOIN series s ON w.series_id = s.series_id
      LEFT JOIN series_genres sg ON s.series_id = sg.series_id
      LEFT JOIN genres g ON sg.genre_id = g.genre_id
      WHERE w.user_id = ?
      GROUP BY s.series_id
      ORDER BY w.added_at DESC;
    `;

			connection.query(q, [friendId], (err2, results) => {
				if (err2) {
					console.error("❌ Error fetching friend's watchlist:", err2);
					return res.status(500).send("Server Error");
				}

				// get friend's name
				connection.query(
					"SELECT name FROM user WHERE id = ?",
					[friendId],
					(err3, userRes) => {
						if (err3 || userRes.length === 0) {
							return res.status(404).send("Friend not found");
						}

						const friend = { id: friendId, name: userRes[0].name };
						res.render("pages/friend-watchlist", {
							friend,
							watchlist: results,
							message: null,
						});
					}
				);
			});
		}
	);
});

// View incoming friend requests
app.get("/watchlist/friends/requests", (req, res) => {
	if (!req.session.user) return res.redirect("/watchlist/login");
	const currentUserId = req.session.user.id;

	const q = `
    SELECT f.sender_id AS id, u.name, u.email, f.status, f.created_at
    FROM friendships f
    JOIN user u ON f.sender_id = u.id
    WHERE f.receiver_id = ? AND f.status = 'pending'
    ORDER BY f.created_at DESC
  `;

	connection.query(q, [currentUserId], (err, requests) => {
		if (err) {
			console.error("❌ Error fetching requests:", err);
			return res.status(500).send("Error fetching requests");
		}
		res.render("pages/friend-requests", { requests, user: req.session.user });
	});
});

// Remove / Unfriend a user
app.delete("/watchlist/friends/remove/:friendId", (req, res) => {
	if (!req.session.user)
		return res.status(401).json({ message: "Unauthorized" });

	const currentUserId = req.session.user.id;
	const friendId = req.params.friendId;

	const q = `
    DELETE FROM friendships
    WHERE 
      (sender_id = ? AND receiver_id = ?)
      OR (sender_id = ? AND receiver_id = ?)
  `;

	connection.query(
		q,
		[currentUserId, friendId, friendId, currentUserId],
		(err, result) => {
			if (err) {
				console.error("❌ Error removing friend:", err);
				return res.status(500).json({ message: "Error removing friend" });
			}

			if (result.affectedRows === 0) {
				return res.status(404).json({ message: "Friendship not found" });
			}

			console.log(
				`✅ Friendship removed between ${currentUserId} and ${friendId}`
			);
			res.json({ success: true, message: "✅ Friend removed successfully." });
		}
	);
});

// ---------------------------------------------------------
// ERROR HANDLING
// ---------------------------------------------------------
// catch-all 404 for unmatched routes
app.all("/", (req, res, next) => {
	next(new ExpressError("Page Not Found", 404));
});

app.use((err, req, res, next) => {
	const { statusCode = 500, message = "Something went wrong" } = err;
	res.status(statusCode).send(message);
});

// START SERVER
app.listen(3000, () => {
	console.log("🚀 Server running at http://localhost:3000");
});
