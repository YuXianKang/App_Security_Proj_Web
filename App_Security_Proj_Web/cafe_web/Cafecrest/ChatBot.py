import random


# Sample data for the chatbot to use
menu_items = {
    "mac n cheese": {"price": 10.50, "description": "Creamy and comforting, perfect for a cozy day."},
    "mbe": {"price": 7.50, "description": "A refreshing and light meal."},
    "egg florentine": {"price": 8.50, "description": "A classic breakfast dish with a savory twist."},
    "hot caffe latte": {"price": 5.20, "description": "A warm and energizing coffee drink."},
    "iced latte": {"price": 5.70, "description": "Cool and refreshing, perfect for a hot day."},
    "hot hazelnut mocha": {"price": 5.90, "description": "A sweet and nutty coffee treat."},
    "iced hazelnut mocha": {"price": 6.10, "description": "A chilled version of our popular hazelnut mocha."},
    "hot americano": {"price": 4.50, "description": "A classic and robust coffee."},
    "iced americano": {"price": 4.70, "description": "The chilled version of an americano."},
    "classic pearl milk tea": {"price": 4.30, "description": "A sweet and creamy tea with chewy pearls."},
    "hot chocolate": {"price": 4.70, "description": "A warm and comforting chocolate drink."},
}

business_info = {
    "hours": "Monday - Sunday 8:30 AM to 8 PM",
    "location": "Ion Orchard 02-707, Singapore",
    "delivery": "We offer delivery through Grab and Deliveroo."}


# Function to process user input and generate a response
def chatbot_response(message):
    message = message.lower()

    if "hello" in message or "hi" in message:
        greetings = ["Hello there!", "Hi!", "Greetings!", "How can I assist you today?"]
        return random.choice(greetings)

    elif "menu" in message:
        return f"Our menu features a delightful range of options, drinks and food. Would you like to search for a specific item?"

    elif "full menu" in message:
        return f"Our menu items are: {', '.join(menu_items.keys())}."

    elif any(item in message for item in menu_items):
        item = [item for item in menu_items if item in message][0]
        return f"A delightful choice! {item.capitalize()} costs ${menu_items[item]['price']} and is described as '{menu_items[item]['description']}."

    elif "hours" in message:
        return f"We're open from {business_info['hours']}. Feel free to drop by or place an order whenever it's convenient for you."

    elif "location" in message:
        return f"You can find us at {business_info['location']}. We're located in the heart of the city, easily accessible by public transport."

    elif "delivery" in message:
        return f"{business_info['delivery']} You can also choose to pick up your order if you're nearby."

    elif "thank you" in message or "thanks" in message:
        return "You're welcome! Is there anything else I can help with? Feel free to ask any questions or explore our menu."

    elif "goodbye" in message or "bye" in message:
        farewells = ["Goodbye!", "Have a great day!", "Take care!"]
        return random.choice(farewells)

    else:
        return "I apologize, I didn't quite understand that. Could you rephrase your question or ask something else?"
