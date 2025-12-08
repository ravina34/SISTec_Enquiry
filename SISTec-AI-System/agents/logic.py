import os
import requests
import json
import logging
import time

logging.basicConfig(level=logging.INFO)

# --- Configuration ---
# API Key is expected to be set in the environment
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent"
MODEL_NAME = "gemini-2.5-flash-preview-09-2025"

def generate_chatbot_response(user_query, max_retries=3):
    """
    Generates a response from the Gemini API using Google Search Grounding.
    Implements exponential backoff for reliability.
    """
    if not GEMINI_API_KEY:
        return "Server Error: GEMINI_API_KEY environment variable is not set.", []
        
    url = f"{API_URL}?key={GEMINI_API_KEY}"
    
    # Define the system instruction for the AI model
    system_prompt = (
        "You are the SISTec AI Assistant, powered by Google Gemini. "
        "You provide accurate and helpful information about SISTec (Sagar Institute of Science & Technology) "
        "and general educational topics. Always maintain a professional, helpful, and courteous tone. "
        "Use the grounding sources provided to ensure accuracy in current events, fees, and syllabus details."
    )

    # Payload for the API request with Search Grounding enabled
    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "tools": [{"google_search": {}}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
    }

    # API request loop with exponential backoff
    for attempt in range(max_retries):
        try:
            response = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=30 # 30 second timeout
            )
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
            
            result = response.json()
            candidate = result.get('candidates', [{}])[0]
            
            # --- Extract Text ---
            text = candidate.get('content', {}).get('parts', [{}])[0].get('text', 'Could not process query or response text is empty.')

            # --- Extract Sources Robustly ---
            sources = []
            grounding_metadata = candidate.get('groundingMetadata')
            
            # The 'groundingMetadata' object is now processed defensively
            if grounding_metadata and grounding_metadata.get('groundingAttributions'):
                for attribution in grounding_metadata['groundingAttributions']:
                    web = attribution.get('web', {})
                    if web.get('uri') and web.get('title'):
                        sources.append({
                            'uri': web['uri'],
                            'title': web['title'],
                        })
            
            return text, sources

        except requests.exceptions.Timeout:
            logging.warning(f"Attempt {attempt + 1}: Request timed out.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Attempt {attempt + 1}: Network/HTTP Error: {e}")
        except Exception as e:
            # This catches the original error and other parsing issues
            logging.error(f"Attempt {attempt + 1}: Unexpected error during generation: {e}")

        # If it's not the last attempt, wait using exponential backoff
        if attempt < max_retries - 1:
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    # If all attempts fail
    return "Server Error: Gemini API is not responding. Please try again later.", []