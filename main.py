import os
import json
import logging
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from facebook_api import FacebookAPI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler('app.log')  # Log to file
    ]
)
logger = logging.getLogger(__name__)

# Also log scheduler events
logging.getLogger('apscheduler').setLevel(logging.INFO)

# Add lock for scheduler jobs
scheduler_lock = threading.Lock()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///transportation.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Facebook API
fb_api = FacebookAPI()

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FacebookCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.String(100), nullable=False)
    access_token = db.Column(db.String(500), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class AssignmentPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    facebook_post_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    is_image = db.Column(db.Boolean, default=False)
    image_path = db.Column(db.String(500))
    ride = db.relationship('ScheduledPost', backref='assignment_post', uselist=False)

class ScheduledPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=False)
    facebook_post_id = db.Column(db.String(100))
    is_posted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assignment_post_id = db.Column(db.Integer, db.ForeignKey('assignment_post.id'))
    
    # Relationship with passengers
    passengers = db.relationship('Passenger', backref='ride', lazy=True)

class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, default=4)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with passengers
    passengers = db.relationship('Passenger', backref='car', lazy=True)

class Passenger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    facebook_id = db.Column(db.String(100))
    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(20))
    profile_pic_url = db.Column(db.String(500))
    destination = db.Column(db.String(200), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('scheduled_post.id'))
    car_id = db.Column(db.Integer, db.ForeignKey('car.id'))
    comment_id = db.Column(db.String(100))
    comment_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def check_scheduled_posts():
    """Check for posts that need to be created on Facebook"""
    if not scheduler_lock.acquire(blocking=False):
        logger.info("Another scheduler job is running, skipping this run")
        return
        
    try:
        logger.info("Checking scheduled posts...")
        
        # Get posts that haven't been posted yet and are due (including past due)
        current_time = datetime.now()
        scheduled_posts = ScheduledPost.query.filter(
            ScheduledPost.is_posted == False,
            ScheduledPost.scheduled_time <= current_time + timedelta(minutes=10)  # Include posts due in next 10 mins
        ).all()
        
        if not scheduled_posts:
            logger.info("No posts to schedule")
            return
        
        logger.info(f"Found {len(scheduled_posts)} posts to schedule")
        
        # Get Facebook credentials
        creds = FacebookCredential.query.order_by(FacebookCredential.last_updated.desc()).first()
        if not creds:
            logger.error("No Facebook credentials found")
            return
        
        fb_api.set_credentials(creds.page_id, creds.access_token)
        
        # Verify credentials before proceeding
        if not fb_api.get_page_info():
            logger.error("Invalid Facebook credentials")
            return
            
        for post in scheduled_posts:
            try:
                logger.info(f"Processing post: ID={post.id}, Message={post.message[:50]}...")
                
                # Post immediately since it's already due
                logger.info(f"Post {post.id} will be posted immediately")
                result = fb_api.create_post(post.message)
                    
                if result and 'id' in result:
                    post.facebook_post_id = result['id']
                    post.is_posted = True
                    db.session.commit()
                    logger.info(f"Post {post.id} processed successfully. Facebook ID: {post.facebook_post_id}")
                else:
                    logger.error(f"Failed to process post {post.id}: No valid response from Facebook API")
            
            except Exception as e:
                logger.exception(f"Error processing post {post.id}: {str(e)}")
                db.session.rollback()
                continue  # Continue with next post even if one fails
                
    except Exception as e:
        logger.exception(f"Error in check_scheduled_posts: {str(e)}")
        db.session.rollback()
    finally:
        scheduler_lock.release()

def sync_post_comments():
    """Sync comments from Facebook posts and extract passenger information"""
    logger.info("Syncing comments from posts...")
    
    # Get Facebook credentials
    creds = FacebookCredential.query.order_by(FacebookCredential.last_updated.desc()).first()
    if not creds:
        logger.error("No Facebook credentials found")
        return
        
    fb_api.set_credentials(creds.page_id, creds.access_token)
    
    # Get active posts from the last 7 days with valid Facebook IDs
    week_ago = datetime.utcnow() - timedelta(days=7)
    posts = ScheduledPost.query.filter(
        ScheduledPost.scheduled_time >= week_ago,
        ScheduledPost.facebook_post_id.isnot(None)
    ).all()
    
    logger.info(f"Found {len(posts)} posts to check for comments")
    total_comments = 0
    
    for post in posts:
        try:
            # Get all comments for this post
            comments = fb_api.get_post_comments(post.facebook_post_id)
            if not comments:
                logger.info(f"No comments found for post {post.id}")
                continue
                
            logger.info(f"Processing {len(comments)} comments for post {post.id}")
            total_comments += len(comments)
            process_comments(comments, post)
            
        except Exception as e:
            logger.exception(f"Error processing comments for post {post.id}: {str(e)}")
            continue
            
    logger.info(f"Sync complete. Processed {total_comments} comments across {len(posts)} posts")

def process_comments(comments, post):
    """Extract passenger information from comments and save to database"""
    logger.info(f"Processing {len(comments)} comments for post {post.id}")
    
    for comment in comments:
        try:
            # Check if comment already processed
            comment_id = comment.get('id')
            if not comment_id:
                logger.warning(f"Skipping comment without ID: {comment}")
                continue
                
            existing = Passenger.query.filter_by(comment_id=comment_id).first()
            if existing:
                logger.debug(f"Comment {comment_id} already processed, skipping")
                continue
            
            # Extract user info
            comment_from = comment.get('from', {})
            if not comment_from:
                logger.warning(f"No user info in comment {comment_id}, skipping")
                continue
                
            message = comment.get('message', '').strip()
            if not message:
                logger.warning(f"Empty comment message from {comment_from.get('name')}, skipping")
                continue
                
            # Create new passenger
            passenger = Passenger(
                facebook_id=comment_from.get('id'),
                name=comment_from.get('name', 'Unknown'),
                gender='unknown',  # Facebook no longer provides gender info
                profile_pic_url=None,  # Will be added if profile pic feature is implemented
                destination=fb_api.parse_destination_from_comment(message),
                post_id=post.id,
                comment_id=comment_id,
                comment_text=message,
                created_at=datetime.utcnow()
            )
            
            db.session.add(passenger)
            db.session.commit()
            logger.info(f"Added new passenger from comment {comment_id}: {passenger.name} -> {passenger.destination}")
            
        except Exception as e:
            logger.exception(f"Error processing comment: {str(e)}")
            db.session.rollback()
            continue

def generate_assignment_summary(post_id):
    """Generate a text summary of car assignments for a ride"""
    ride = ScheduledPost.query.get(post_id)
    if not ride:
        return None
        
    cars = Car.query.filter_by(is_active=True).all()
    summary = []
    
    # Add ride details
    summary.append(f"🚗 Ride Assignments for {ride.scheduled_time.strftime('%B %d, %Y at %H:%M')}")
    summary.append("")  # Empty line
    
    # Add assignments for each car
    for car in cars:
        passengers = Passenger.query.filter_by(post_id=ride.id, car_id=car.id).all()
        if passengers:
            summary.append(f"📍 {car.name} ({len(passengers)}/{car.capacity} passengers):")
            for i, passenger in enumerate(passengers, 1):
                destination = passenger.destination or "No destination specified"
                summary.append(f"  {i}. {passenger.name} → {destination}")
            summary.append("")  # Empty line
    
    # Add unassigned passengers
    unassigned = Passenger.query.filter_by(post_id=ride.id, car_id=None).all()
    if unassigned:
        summary.append("❗ Unassigned Passengers:")
        for i, passenger in enumerate(unassigned, 1):
            destination = passenger.destination or "No destination specified"
            summary.append(f"  {i}. {passenger.name} → {destination}")
        summary.append("")
    
    return "\n".join(summary)

def post_assignments(post_id, use_image=False):
    """Post car assignments to Facebook"""
    ride = ScheduledPost.query.get(post_id)
    if not ride:
        return False
        
    # Get Facebook credentials
    creds = FacebookCredential.query.order_by(FacebookCredential.last_updated.desc()).first()
    if not creds:
        logger.error("No Facebook credentials found")
        return False
        
    fb_api.set_credentials(creds.page_id, creds.access_token)
    
    # Delete existing assignment post if it exists
    if ride.assignment_post and ride.assignment_post.facebook_post_id:
        fb_api.delete_post(ride.assignment_post.facebook_post_id)
    
    # Generate assignment summary
    summary = generate_assignment_summary(post_id)
    if not summary:
        return False
    
    result = None
    if use_image:
        # Generate image of assignments (implementation to be added)
        pass
    else:
        result = fb_api.create_post(summary)
    
    if result and 'id' in result:
        # Create or update assignment post
        if ride.assignment_post:
            assignment_post = ride.assignment_post
        else:
            assignment_post = AssignmentPost()
            ride.assignment_post = assignment_post
            
        assignment_post.facebook_post_id = result['id']
        assignment_post.is_image = use_image
        db.session.commit()
        return True
        
    return False

# Scheduler context wrappers
def check_scheduled_posts_with_context():
    with app.app_context():
        check_scheduled_posts()

def sync_post_comments_with_context():
    with app.app_context():
        sync_post_comments()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get Facebook page info
    page_info = None
    creds = FacebookCredential.query.order_by(FacebookCredential.last_updated.desc()).first()
    
    if creds:
        fb_api.set_credentials(creds.page_id, creds.access_token)
        page_info = fb_api.get_page_info()
    
    # Get stats
    stats = {
        'scheduled_rides': ScheduledPost.query.filter_by(is_posted=False).count(),
        'active_rides': ScheduledPost.query.filter_by(is_posted=True).count(),
        'total_passengers': Passenger.query.count(),
        'available_cars': Car.query.filter_by(is_active=True).count()
    }
    
    # Get upcoming rides
    upcoming_rides = ScheduledPost.query.filter(
        ScheduledPost.scheduled_time >= datetime.utcnow()
    ).order_by(ScheduledPost.scheduled_time).limit(5).all()
    
    return render_template('dashboard.html', 
                          page_info=page_info,
                          stats=stats,
                          upcoming_rides=upcoming_rides)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        page_id = request.form.get('page_id')
        access_token = request.form.get('access_token')
        
        if page_id and access_token:
            # Test the credentials
            test_api = FacebookAPI(page_id, access_token)
            page_info = test_api.get_page_info()
            
            if page_info:
                # Save the credentials
                cred = FacebookCredential(page_id=page_id, access_token=access_token)
                db.session.add(cred)
                db.session.commit()
                
                flash('Facebook credentials saved successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid Facebook credentials', 'danger')
        else:
            flash('Please provide both Page ID and Access Token', 'warning')
            
    return render_template('settings.html')

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'danger')
        return redirect(url_for('settings'))
        
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('settings'))
        
    user = User.query.get(current_user.id)
    if not user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('settings'))
        
    user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/rides')
@login_required
def rides():
    posts = ScheduledPost.query.order_by(ScheduledPost.scheduled_time.desc()).all()
    
    # Get passenger counts for each post
    for post in posts:
        post.passengers = Passenger.query.filter_by(post_id=post.id).all()
    
    return render_template('rides.html', posts=posts, now=datetime.utcnow())

@app.route('/ride/new', methods=['GET', 'POST'])
@login_required
def new_ride():
    if request.method == 'POST':
        message = request.form.get('message')
        scheduled_date = request.form.get('date')
        scheduled_time = request.form.get('time')
        
        if message and scheduled_date and scheduled_time:
            try:
                # Combine date and time
                scheduled_datetime = datetime.strptime(f"{scheduled_date} {scheduled_time}", "%Y-%m-%d %H:%M")
                
                # Create the scheduled post
                post = ScheduledPost(
                    message=message,
                    scheduled_time=scheduled_datetime
                )
                db.session.add(post)
                db.session.commit()
                
                flash('Ride scheduled successfully', 'success')
                return redirect(url_for('rides'))
            except Exception as e:
                flash(f'Error scheduling ride: {str(e)}', 'danger')
        else:
            flash('Please fill all required fields', 'warning')
            
    return render_template('new_ride.html')

@app.route('/ride/<int:ride_id>')
@login_required
def ride_detail(ride_id):
    ride = ScheduledPost.query.get_or_404(ride_id)
    passengers = Passenger.query.filter_by(post_id=ride.id).all()
    cars = Car.query.filter_by(is_active=True).all()
    
    return render_template('ride_detail.html', 
                          ride=ride, 
                          passengers=passengers,
                          cars=cars)

@app.route('/ride/<int:ride_id>/delete', methods=['POST'])
@login_required
def delete_ride(ride_id):
    ride = ScheduledPost.query.get_or_404(ride_id)
    
    try:
        # Delete associated passengers first
        Passenger.query.filter_by(post_id=ride.id).delete()
        
        # Delete the ride
        db.session.delete(ride)
        db.session.commit()
        
        flash('Ride deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting ride: {str(e)}', 'danger')
    
    return redirect(url_for('rides'))

@app.route('/cars')
@login_required
def cars():
    cars_list = Car.query.all()
    return render_template('cars.html', cars=cars_list)

@app.route('/car/new', methods=['GET', 'POST'])
@login_required
def new_car():
    if request.method == 'POST':
        name = request.form.get('name')
        capacity = request.form.get('capacity')
        description = request.form.get('description')
        is_active = bool(request.form.get('is_active'))
        
        if name and capacity:
            car = Car(
                name=name,
                capacity=int(capacity),
                description=description,
                is_active=is_active
            )
            db.session.add(car)
            db.session.commit()
            
            flash('Car added successfully', 'success')
            return redirect(url_for('cars'))
        else:
            flash('Please provide name and capacity', 'warning')
            
    return render_template('new_car.html')

@app.route('/car/<int:car_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_car(car_id):
    car = Car.query.get_or_404(car_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        capacity = request.form.get('capacity')
        description = request.form.get('description')
        is_active = bool(request.form.get('is_active'))
        
        if name and capacity:
            car.name = name
            car.capacity = int(capacity)
            car.description = description
            car.is_active = is_active
            
            db.session.commit()
            
            flash('Car updated successfully', 'success')
            return redirect(url_for('cars'))
        else:
            flash('Please provide name and capacity', 'warning')
    
    return render_template('new_car.html', car=car)

@app.route('/car/<int:car_id>/toggle', methods=['POST'])
@login_required
def toggle_car_status(car_id):
    car = Car.query.get_or_404(car_id)
    
    try:
        car.is_active = not car.is_active
        db.session.commit()
        
        status = 'activated' if car.is_active else 'deactivated'
        flash(f'Car {car.name} {status} successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating car status: {str(e)}', 'danger')
    
    return redirect(url_for('cars'))

@app.route('/car/<int:car_id>/delete', methods=['POST'])
@login_required
def delete_car(car_id):
    car = Car.query.get_or_404(car_id)
    
    try:
        # Update any passengers assigned to this car
        Passenger.query.filter_by(car_id=car.id).update({Passenger.car_id: None})
        
        # Delete the car
        db.session.delete(car)
        db.session.commit()
        
        flash('Car deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting car: {str(e)}', 'danger')
    
    return redirect(url_for('cars'))

@app.route('/api/sync-comments', methods=['POST'])
@login_required
def api_sync_comments():
    try:
        sync_post_comments()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/assign-passenger', methods=['POST'])
@login_required
def api_assign_passenger():
    passenger_id = request.form.get('passenger_id')
    car_id = request.form.get('car_id')
    
    if passenger_id:
        try:
            passenger = Passenger.query.get(passenger_id)
            if not passenger:
                return jsonify({"success": False, "error": "Passenger not found"}), 404

            # If car_id is empty string or None, we're unassigning
            if not car_id:
                passenger.car_id = None
                db.session.commit()
                return jsonify({"success": True})

            # Check car exists and has capacity
            car = Car.query.get(car_id)
            if not car:
                return jsonify({"success": False, "error": "Car not found"}), 404

            # Count current passengers in the car
            current_passengers = Passenger.query.filter_by(car_id=car.id).count()
            
            # Check if adding this passenger would exceed capacity
            if current_passengers >= car.capacity:
                return jsonify({
                    "success": False, 
                    "error": f"Cannot assign passenger. Car {car.name} is at full capacity ({car.capacity} passengers)"
                }), 400

            passenger.car_id = car_id
            db.session.commit()
            return jsonify({"success": True})
            
        except Exception as e:
            db.session.rollback()
            logger.exception(f"Error assigning passenger {passenger_id}: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
    
    return jsonify({"success": False, "error": "Missing required parameters"}), 400

@app.route('/api/add-passenger', methods=['POST'])
@login_required
def api_add_passenger():
    try:
        # Get form data
        name = request.form.get('name')
        destination = request.form.get('destination')
        gender = request.form.get('gender')
        post_id = request.form.get('post_id')
        car_id = request.form.get('car_id') or None
        
        if not name or not destination or not post_id:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        # Create new passenger
        passenger = Passenger(
            name=name,
            destination=destination,
            gender=gender,
            post_id=post_id,
            car_id=car_id
        )
        
        db.session.add(passenger)
        db.session.commit()
        
        return jsonify({"success": True, "passenger_id": passenger.id})
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error adding passenger: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/edit-passenger', methods=['POST'])
@login_required
def api_edit_passenger():
    try:
        passenger_id = request.form.get('passenger_id')
        passenger = Passenger.query.get(passenger_id)
        
        if not passenger:
            return jsonify({"success": False, "error": "Passenger not found"}), 404
            
        # Update fields
        passenger.name = request.form.get('name', passenger.name)
        passenger.destination = request.form.get('destination', passenger.destination)
        passenger.gender = request.form.get('gender', passenger.gender)
        
        # Only update car_id if provided
        if 'car_id' in request.form:
            passenger.car_id = request.form.get('car_id') or None
            
        db.session.commit()
        return jsonify({"success": True})
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error editing passenger: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/delete-passenger', methods=['POST'])
@login_required
def api_delete_passenger():
    try:
        passenger_id = request.form.get('passenger_id')
        passenger = Passenger.query.get(passenger_id)
        
        if not passenger:
            return jsonify({"success": False, "error": "Passenger not found"}), 404
            
        db.session.delete(passenger)
        db.session.commit()
        return jsonify({"success": True})
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting passenger: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/post-assignments', methods=['POST'])
@login_required
def api_post_assignments():
    try:
        data = request.get_json()
        post_id = data.get('post_id')
        use_image = data.get('use_image', False)
        
        if not post_id:
            return jsonify({"success": False, "error": "Missing post ID"}), 400
        
        success = post_assignments(post_id, use_image)
        return jsonify({"success": success})
        
    except Exception as e:
        logger.exception(f"Error posting assignments: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="Server error"), 500

# Initialize the app
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

# Start the scheduler outside the app context
scheduler = None

def init_scheduler():
    global scheduler
    if scheduler is None:
        scheduler = BackgroundScheduler()
        scheduler.add_jobstore(MemoryJobStore(), 'default')

        # Add jobs with proper context management
        scheduler.add_job(
            check_scheduled_posts_with_context,
            'interval',
            minutes=1,
            id='check_posts_job',
            replace_existing=True
        )

        scheduler.add_job(
            sync_post_comments_with_context,
            'interval',
            minutes=5,
            id='sync_comments_job',
            replace_existing=True
        )

        scheduler.start()
        logger.info("Scheduler initialized and started")

def cleanup_scheduler():
    global scheduler
    if scheduler:
        scheduler.shutdown()
        scheduler = None
        logger.info("Scheduler shut down")

if __name__ == '__main__':
    import os
    
    # Check if we're running the main process (not the reloader)
    try:
        if not os.environ.get('WERKZEUG_RUN_MAIN'):
            logger.info("Skipping scheduler initialization in reloader process")
        else:
            init_scheduler()
    except Exception as e:
        logger.error(f"Error during scheduler initialization: {str(e)}")
        
    try:
        app.run(debug=True)
    finally:
        cleanup_scheduler()
