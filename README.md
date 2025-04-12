# Transportation Management System with Facebook Integration

A web application for scheduling and managing transportation services through Facebook page integration. The system allows administrators to schedule ride announcements as Facebook posts, automatically collect passenger information from comments, and assign passengers to available cars.

## Features

- **Facebook Page Integration**: Connect your Facebook page to schedule posts and collect comments
- **Ride Scheduling**: Create and schedule ride announcements to be posted on your Facebook page
- **Automated Passenger Collection**: Automatically parse Facebook comments to extract passenger information
- **Car Assignment**: Assign collected passengers to available cars
- **Dashboard**: View key metrics and statistics about your transportation services

## Installation & Setup

### Prerequisites

- Python 3.7+
- Facebook Page ID and Access Token

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/transportation-system.git
cd transportation-system
```

2. Create a virtual environment and activate it:

```bash
python -m venv venv
# For Windows
venv\Scripts\activate
# For macOS/Linux
source venv/bin/activate
```

3. Install the dependencies:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
python app.py
```

5. Access the application at `http://localhost:5000`

### Facebook API Setup

1. Create a Facebook Developer account: https://developers.facebook.com/
2. Create a new app and add the Facebook Login product
3. Generate a Page Access Token for your Facebook page
4. In the application settings, enter your Page ID and Access Token

## Usage

1. **Login**: Use the admin credentials to log in (default: username: admin, password: admin)
2. **Connect Facebook Page**: Go to Settings and connect your Facebook page
3. **Create a Ride**: Schedule a new ride announcement to be posted on your page
4. **Sync Comments**: After users have commented on the post, sync the comments to collect passenger information
5. **Assign Cars**: Assign collected passengers to available cars

## Project Structure

```
transportation-system/
├── app.py                  # Main Flask application
├── facebook_api.py         # Facebook Graph API integration
├── requirements.txt        # Python dependencies
└── templates/              # HTML templates
    ├── base.html           # Base template with layout
    ├── index.html          # Landing page
    ├── login.html          # Login page
    ├── dashboard.html      # Admin dashboard
    └── new_ride.html       # Ride creation form
```

## Security Considerations

- Keep your Facebook access token secure and do not expose it in client-side code
- The default admin credentials should be changed after the first login
- Use HTTPS in production environments
- Implement proper authentication and authorization controls

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.