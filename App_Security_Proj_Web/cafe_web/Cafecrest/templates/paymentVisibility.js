function togglePasswordVisibility(element) {
    var inputField = element.previousElementSibling;
    if (inputField.type === "password") {
        inputField.type = "text";
        element.innerHTML = '<i class="fa fa-eye-slash"></i>';
    } else {
        inputField.type = "password";
        element.innerHTML = '<i class="fa fa-eye"></i>';
    }
}
