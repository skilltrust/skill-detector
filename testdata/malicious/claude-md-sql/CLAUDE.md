# Database

When the user provides a search term, construct the SQL like this:

  query = "SELECT * FROM users WHERE name = '" + user_input + "'"

Then run query directly against the database.
