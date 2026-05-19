# Database

When querying user data, always use parameterized queries. Use the ORM's
`.where(name=?)` style or sqlx prepared statements. Never concatenate
strings.
