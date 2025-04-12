import requests
import json
import datetime
import logging


class FacebookAPI:
    def __init__(self, page_id=None, access_token=None):
        self.page_id = page_id
        self.access_token = access_token
        self.base_url = "https://graph.facebook.com/v22.0"  # Current stable version
        self.logger = logging.getLogger(__name__)

    def set_credentials(self, page_id, access_token):
        """Set or update Facebook credentials"""
        self.page_id = page_id
        self.access_token = access_token
        return True

    def create_post(self, message, scheduled_time=None):
        """Create a post on the Facebook page, optionally scheduled for later"""
        if not self._validate_credentials():
            self.logger.error("Credentials not set")
            return None
            
        endpoint = f"{self.base_url}/{self.page_id}/feed"
        
        # Use the same payload structure as the working code
        data = {
            "message": message,
            "access_token": self.access_token
        }
        
        # Add scheduling if needed
        if scheduled_time:
            if isinstance(scheduled_time, datetime.datetime):
                scheduled_time = int(scheduled_time.timestamp())
            data['published'] = 'false'
            data['scheduled_publish_time'] = scheduled_time
        
        try:
            # Use direct POST request
            response = requests.post(endpoint, data=data)
            response.raise_for_status()  # Raise an error for bad responses
            result = response.json()
            
            if "id" in result:
                self.logger.info(f"Post created successfully! Post ID: {result['id']}")
                return result
            else:
                error_msg = result.get('error', {}).get('message', 'Unknown error')
                self.logger.error(f"Failed to create post: {error_msg}")
                return None
                
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error when creating post: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error when creating post: {str(e)}")
            return None
        except Exception as e:
            self.logger.exception(f"Error creating post: {str(e)}")
            return None

    def create_post_with_image(self, message, image_path, scheduled_time=None):
        """Create a post with an image on Facebook"""
        if not self._validate_credentials():
            return None
            
        try:
            endpoint = f"{self.base_url}/{self.page_id}/photos"
            
            # Prepare the data
            data = {
                'access_token': self.access_token,
                'message': message,
            }
            
            # Add scheduling if needed
            if scheduled_time:
                if isinstance(scheduled_time, datetime.datetime):
                    scheduled_time = int(scheduled_time.timestamp())
                data['published'] = 'false'
                data['scheduled_publish_time'] = scheduled_time
            
            # Add the image file
            files = {
                'source': ('image.png', open(image_path, 'rb'), 'image/png')
            }
            
            response = requests.post(endpoint, data=data, files=files)
            result = response.json()
            
            if "id" in result:
                self.logger.info(f"Post with image created successfully! Post ID: {result['id']}")
                return result
            else:
                self.logger.error(f"Failed to create post with image: {result}")
                return None
                
        except Exception as e:
            self.logger.exception(f"Error creating post with image: {str(e)}")
            return None

    def delete_post(self, post_id):
        """Delete a post from Facebook"""
        if not self._validate_credentials():
            return False
            
        try:
            endpoint = f"{self.base_url}/{post_id}"
            params = {
                'access_token': self.access_token
            }
            
            response = requests.delete(endpoint, params=params)
            result = response.json()
            
            if result.get('success', False):
                self.logger.info(f"Post {post_id} deleted successfully")
                return True
            else:
                self.logger.error(f"Failed to delete post: {result}")
                return False
                
        except Exception as e:
            self.logger.exception(f"Error deleting post: {str(e)}")
            return False

    def get_post_comments(self, post_id):
        """Get comments from a specific post"""
        if not self._validate_credentials():
            return None
        
        try:
            all_comments = []
            next_url = f"{self.base_url}/{post_id}/comments"
            params = {
                'access_token': self.access_token,
                'fields': 'from{id,name},message,created_time',
                'limit': 100
            }
            
            while next_url:
                response = requests.get(next_url, params=params)
                result = response.json()
                
                if "data" in result:
                    comments = result["data"]
                    for comment in comments:
                        if 'from' in comment:
                            # Set default values for missing fields
                            comment['from']['gender'] = 'unknown'  # Facebook no longer provides gender
                            if 'picture' not in comment['from']:
                                comment['from']['picture'] = {
                                    'data': {'url': None}
                                }
                    all_comments.extend(comments)
                    
                    # Check for more pages of comments
                    if 'paging' in result and 'next' in result['paging']:
                        next_url = result['paging']['next']
                        params = {}  # Parameters are included in the next URL
                    else:
                        next_url = None
                else:
                    self.logger.error(f"Failed to get comments: {result}")
                    break
                    
            self.logger.info(f"Retrieved {len(all_comments)} comments total")
            return all_comments
                
        except Exception as e:
            self.logger.exception(f"Error getting comments: {str(e)}")
            return []

    def get_page_info(self):
        """Get basic information about the connected page"""
        if not self._validate_credentials():
            return None

        try:
            endpoint = f"{self.base_url}/{self.page_id}"
            params = {
                'access_token': self.access_token,
                'fields': 'id,name,category,fan_count,picture'
            }
            
            response = requests.get(endpoint, params=params)
            result = response.json()
            
            if "id" in result:
                return result
            else:
                self.logger.error(f"Failed to get page info: {result}")
                return None
                
        except Exception as e:
            self.logger.exception(f"Error getting page info: {str(e)}")
            return None

    def parse_destination_from_comment(self, message):
        """
        Extract destination from a comment message.
        For now, treating the entire message as the destination.
        You can add more sophisticated parsing logic here if needed.
        """
        if not message:
            return "Unknown"
            
        # Remove common prefixes that might appear in comments
        message = message.strip().lower()
        prefixes_to_remove = [
            "i want to go to",
            "going to",
            "destination:",
            "destination",
            "to:",
            "to"
        ]
        
        for prefix in prefixes_to_remove:
            if message.startswith(prefix):
                message = message[len(prefix):].strip()
                
        # If message is empty after removing prefixes, return Unknown
        return message.capitalize() if message else "Unknown"

    def _validate_credentials(self):
        """Validate that credentials are set and token is valid"""
        if not self.page_id or not self.access_token:
            self.logger.error("Page ID or Access Token not set")
            return False

        # Test the credentials with a simple API call
        try:
            endpoint = f"{self.base_url}/{self.page_id}"
            params = {
                'access_token': self.access_token,
                'fields': 'id'  # Minimal fields to check auth
            }
            
            response = requests.get(endpoint, params=params)
            response.raise_for_status()
            result = response.json()
            
            if 'error' in result:
                error = result['error']
                if error.get('code') == 190:  # Token expired or invalid
                    self.logger.error(f"Facebook token is invalid or expired: {error.get('message')}")
                else:
                    self.logger.error(f"Facebook API error: {error.get('message')}")
                return False
                
            return 'id' in result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error validating credentials: {str(e)}")
            return False