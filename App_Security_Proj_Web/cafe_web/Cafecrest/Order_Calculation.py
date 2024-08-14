def calculate_subtotal(order_items):
    subtotal = 0
    for item in order_items:
        subtotal += item.quantity * item.item_price
    subtotal = round(subtotal, 2)
    return subtotal


def calculate_sales_tax(subtotal):
    return round(0.09 * subtotal, 2)


def calculate_delivery_amount(collection_type):
    return 5 if collection_type == 'delivery' else 0


def calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_type):
    if collection_type == 'delivery':
        return round(subtotal + sales_tax + delivery_amount, 2)
    else:
        return round(subtotal + sales_tax, 2)
