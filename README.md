Project Name: Potter's Queue
Owner: Cynthia Dodzi
Twitter: @cynthiadodzi
LinkedIn: @dahesey

Architecture


APIs and Methods

GET /attendees:
Description: Retrieve a list of all attendees.
Response: JSON array containing objects representing each attendee, including their name and contribution details.




POST /attendees:
Description: Add a new attendee to the database.
Request Body: JSON object containing the new attendee's name and contribution details.
Response: JSON object confirming the addition of the attendee, including a unique identifier.

GET /attendees/:id:
Description: Retrieve details of a specific attendee by their unique identifier.
Parameters: id (Attendee's unique identifier).
Response: JSON object containing the attendee's name and contribution details.

PUT /attendees/:id:
Description: Update details of a specific attendee.
Parameters: id (Attendee's unique identifier).
Request Body: JSON object containing the updated attendee's name and contribution details.
Response: JSON object confirming the update of the attendee.

DELETE /attendees/:id:
Description: Delete a specific attendee from the database.
Parameters: id (Attendee's unique identifier).
Response: JSON object confirming the deletion of the attendee.


Authentication Endpoints:

POST /auth/login:
Description: Authenticate users and generate access tokens.
Request Body: JSON object containing user credentials (e.g., username and password).
Response: JSON object containing an access token if authentication is successful.

POST /auth/register:
Description: Register new users.
Request Body: JSON object containing user registration information (e.g., username, email, password).
Response: JSON object confirming the successful registration of the user.

Contributions Endpoints:

GET /contributions:
Description: Retrieve a list of all contributions.
Response: JSON array containing objects representing each contribution, including contributor's name, amount, date, etc.



POST /contributions:
Description: Add a new contribution.
Request Body: JSON object containing contributor's name, contribution amount, and optional details.
Response: JSON object confirming the addition of the contribution, including a unique identifier.

GET /contributions/:id:
Description: Retrieve details of a specific contribution by its unique identifier.
Parameters: id (Contribution's unique identifier).
Response: JSON object containing details of the contribution.

PUT /contributions/:id:
Description: Update details of a specific contribution.
Parameters: id (Contribution's unique identifier).
Request Body: JSON object containing the updated contribution details.
Response: JSON object confirming the update of the contribution.

DELETE /contributions/:id:
Description: Delete a specific contribution.
Parameters: id (Contribution's unique identifier).
Response: JSON object confirming the deletion of the contribution.


Data Modelling




User Stories

Title: Recording Church Attendee Contributions

As a: Church administrator

I want to: Easily record the names of attendees and their contributions during church services

So that: We can maintain accurate records of attendance and financial contributions for reporting and planning purposes.

Acceptance Criteria:

As a church administrator, I should be able to access the web application from any device with an internet connection.
I should be able to log in securely using my username and password.
Once logged in, I should see a user-friendly interface with options to record attendee names and their contributions.
When recording attendee names, the system should validate the input to ensure it's a valid name format.
When recording contributions, the system should require the attendee's name, contribution amount, and date.
The system should provide feedback confirming successful recording of attendee names and contributions.
I should be able to view a list of all recorded attendees and their contributions.
I should be able to edit or delete recorded attendee names and contributions if needed.
The system should store all data securely and maintain data integrity to prevent unauthorized access or tampering.
The system should generate reports summarizing attendance and financial contributions over specific time periods if requested.


Title: Managing Front Desk Operations at the Church

As a: Church front desk administrator

I want to: Efficiently manage front desk operations to assist church members and visitors

So that: I can provide a welcoming environment and support the smooth functioning of church activities

Acceptance Criteria:

Login and Access:

As a front desk administrator, I should be able to log in securely to the church management system using my credentials.
View and Update Information:

Upon logging in, I should see an intuitive dashboard displaying upcoming church events, service schedules, and announcements.
I should be able to view and update information such as service times, contact details, and staff schedules as needed.
Member and Visitor Assistance:

I should be able to register new church members and update their contact information in the system.
When visitors arrive, I should be able to greet them warmly and provide assistance, including directing them to appropriate areas of the church and answering any questions they may have.
Facility Management:

I should be able to manage room bookings for church events, meetings, and gatherings.
I should be able to check the availability of church facilities and assist in scheduling events accordingly.
Resource Management:

I should be able to maintain an inventory of church resources such as Bibles, hymnals, and literature.
I should be able to track the distribution and return of resources, as well as manage requests for additional materials.
Communication and Coordination:

I should be able to communicate effectively with church staff, volunteers, and members via email, phone calls, or messaging within the system.
I should be able to coordinate volunteer schedules, assign tasks, and send reminders for upcoming events or duties.


Title: Managing Church Finances Effectively

As a: Church accountant

I want to: Streamline financial management processes for the church

So that: I can ensure accurate financial records, compliance with regulations, and support informed decision-making by church leadership

Acceptance Criteria:

Login and Access:

As a church accountant, I should be able to securely log in to the church management system using my credentials.
View and Update Financial Data:

Upon logging in, I should have access to a dashboard displaying financial information such as income, expenses, and balances.
I should be able to view and update financial transactions including donations, expenditures, and budget allocations.
Recording Transactions:

I should be able to record donations received from church members and visitors, specifying the amount, date, and purpose.
I should be able to record expenses incurred by the church, categorizing them appropriately (e.g., utilities, salaries, maintenance).
Generating Financial Reports:

I should be able to generate financial reports including balance sheets, income statements, and cash flow statements.
Reports should be customizable by date range, fund, or category to provide detailed insights into the church's financial status.
Budget Management:

I should be able to create and manage budgets for different church ministries, programs, and projects.
I should be able to monitor budget vs. actual spending and adjust allocations as needed to ensure financial stability and alignment with church priorities.
Compliance and Accountability:

I should ensure compliance with financial regulations and church policies, maintaining accurate records and documentation for audits I should implement internal controls to safeguard church assets and prevent fraud or misuse of funds

Screenshot

