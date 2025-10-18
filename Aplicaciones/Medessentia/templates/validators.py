from django.core.exceptions import ValidationError

def validar_cedula_ecuatoriana(cedula):
    if len(cedula) != 10 or not cedula.isdigit():
        raise ValidationError("La cédula debe tener 10 dígitos numéricos.")

    provincia = int(cedula[:2])
    if provincia < 1 or provincia > 24:
        raise ValidationError("La cédula debe pertenecer a una provincia válida (01-24).")

    # Validación con el algoritmo oficial
    total = 0
    for i in range(9):
        num = int(cedula[i])
        if i % 2 == 0:  # posiciones impares (0 index)
            num *= 2
            if num > 9:
                num -= 9
        total += num

    verificador = 10 - (total % 10) if total % 10 != 0 else 0
    if verificador != int(cedula[9]):
        raise ValidationError("Cédula ecuatoriana no válida.")
