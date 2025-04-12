import requests
import time

# Your access token, page ID, and message to post
ACCESS_TOKEN = "EAASpemNBam4BOwzt454PqpSlvtcmx2QQ1YLicCjxaZCQPAUo4ZClkpmiYJPcjuhrF4w4xNsAlcjuqQDt1fRFZBlJJy9ZBGS34zZB93pq4ZAvkTBZCSZC6j4XIPqZAIYDIT34Kgr9ZAZAZCZAuGD9RX9Tbw0JXZAaRUVTTZCURdGR5v3cix3SVlFrHZC0PPB05TJEzRA1jmpEKGQnZCeoQjVsGwpiYHbCl3m2r"
PAGE_ID = "653667717822521"
MESSAGE = "This is an afadfasdf adf utomated post using the Facebook Graph API."

# Graph API base URL
BASE_URL = "https://graph.facebook.com/v22.0/"

def post_on_facebook():
    """Posts a message on the Facebook Page and returns the post ID."""
    url = f"{BASE_URL}{PAGE_ID}/feed"
    payload = {
        "message": MESSAGE,
        "access_token": ACCESS_TOKEN
    }
    response = requests.post(url, data=payload)
    result = response.json()

    if "id" in result:
        print(f"Post created successfully! Post ID: {result['id']}")
        return result["id"]
    else:
        print("Failed to create post:", result)
        return None

def get_comments(post_id):
    """Retrieves comments from a given post along with usernames and gender."""
    url = f"{BASE_URL}{post_id}/comments"
    payload = {
        "fields": "from{name,id,gender,picture},message",
        "access_token": ACCESS_TOKEN
    }
    response = requests.get(url, params=payload)
    result = response.json()

    if "data" in result:
        print("\nComments on the post:")
        for comment in result["data"]:
            user = comment["from"]
            name = user.get("name", "Unknown")
            gender = user.get("gender", "Unknown")
            message = comment["message"]
            print(f"{name} ({gender}): {message}")
    else:
        print("No comments found or an error occurred:", result)

if __name__ == "__main__":
    post_id = post_on_facebook()
    
    if post_id:
        wait_time = int(input("Enter the wait time (in seconds) before fetching comments: "))
        print(f"Waiting for {wait_time} seconds...")
        time.sleep(wait_time)  # Wait for comments to be added
        
        get_comments(post_id)
