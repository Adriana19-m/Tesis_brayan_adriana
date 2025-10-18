from django.contrib.auth.models import User, Group

# Crear grupos
g_admin, _ = Group.objects.get_or_create(name='Administrador')
g_doctor, _ = Group.objects.get_or_create(name='Doctor')
g_paciente, _ = Group.objects.get_or_create(name='Paciente')

# Crear admin
admin, created = User.objects.get_or_create(username='admin_test')
if created:
    admin.email = 'admin@example.com'
    admin.is_staff = True
    admin.set_password('adminpass')
    admin.save()
admin.groups.add(g_admin)

# Crear doctor
doctor, created = User.objects.get_or_create(username='doctor_test')
if created:
    doctor.email = 'doc@example.com'
    doctor.set_password('docpass')
    doctor.save()
doctor.groups.add(g_doctor)

# Crear paciente
pac, created = User.objects.get_or_create(username='paciente_test')
if created:
    pac.email = 'pac@example.com'
    pac.set_password('pacpass')
    pac.save()
pac.groups.add(g_paciente)

print('Usuarios creados/asegurados: admin_test/adminpass, doctor_test/docpass, paciente_test/pacpass')