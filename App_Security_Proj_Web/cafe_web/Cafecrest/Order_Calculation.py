def calculate_subtotal(cart):
    subtotal = 0
    for item in cart:
        if isinstance(item, dict) and 'quantity' in item and 'price' in item:
            subtotal += item['quantity'] * item['price']
    subtotal = round(subtotal, 2)
    return subtotal


def calculate_sales_tax(subtotal):
    return round(0.09 * subtotal, 2)


def calculate_delivery_amount(collection_types):
    return 5 if collection_types == 'delivery' else 0


def calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_types):
    if collection_types == 'delivery':
        return round(subtotal + sales_tax + delivery_amount, 2)
    else:
        return round(subtotal + sales_tax, 2)