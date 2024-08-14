import shelve

with shelve.open('order.db', 'r') as order_db:
    # Read 'orders' dictionary
    if 'orders' in order_db:
        orders = order_db['orders']
        print("Orders:")
        for order_id, order_details in orders.items():
            print(f"Order ID: {order_id}")
            for key, value in order_details.items():
                print(f"    {key}: {value}")
    else:
        print("No orders found.")

    # Read 'cart' dictionary
    if 'cart' in order_db:
        cart = order_db['cart']
        print("\nCart:")
        for order_id, cart_items in cart.items():
            print(f"Order ID: {order_id}")
            for item in cart_items:
                print(f"    {item}")
    else:
        print("No items in the cart.")

Delete = input('Wanna Delete All Stored Data? y/n: ')
if Delete == 'y':
    with shelve.open('order.db', 'w') as order_db:
        order_db.clear()
