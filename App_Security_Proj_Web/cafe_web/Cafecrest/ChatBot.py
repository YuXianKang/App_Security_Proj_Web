# Sample data for the chatbot to use
menu_items = {
    "mac n cheese": 10.50,
    "mbe": 7.50,
    "egg florentine": 8.50,
    "hot caffe latte": 5.20,
    "iced latte": 5.70,
    "hot hazelnut mocha": 5.90,
    "iced hazelnut mocha": 6.10,
    "hot americano": 4.50,
    "iced americano": 4.70,
    "classic pearl milk tea": 4.30,
    "hot chocolate": 4.70,

}

business_info = {
    "hours": "Monday - Sunday 8:30 AM to 8 PM",
    "location": "Ion Orchard 02-707, Singapore",
    "delivery": "We offer delivery through Grab and Deliveroo."}


# Function to process user input and generate a response
def chatbot_response(message):
    message = message.lower()
    if "menu" in message:
        return f"Our menu items are: {', '.join(menu_items.keys())}."
    elif any(item in message for item in menu_items):
        item = [item for item in menu_items if item in message][0]
        return f"The price of {item} is ${menu_items[item]}."
    elif "hours" in message:
        return f"Our business hours are {business_info['hours']}."
    elif "location" in message:
        return f"We are located at {business_info['location']}."
    elif "delivery" in message:
        return business_info['delivery']
    elif "thank you" in message or "thanks" in message:
        return "You're welcome! Is there anything else I can help with?"
    else:
        return "I'm not sure I understand. Can you ask something else?"
