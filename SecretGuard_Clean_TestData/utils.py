def format_title(text):
    return text.strip().title()


def is_valid_age(age):
    return isinstance(age, int) and 1 <= age <= 100


def show_message(message):
    print(message)
