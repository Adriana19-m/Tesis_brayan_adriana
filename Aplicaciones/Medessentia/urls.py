from django.urls import path
from django.contrib.auth import views as auth_views
from Aplicaciones.Medessentia import views

urlpatterns = [
    path("", views.home_publico, name="home_publico"),
    # -------------------------
    # Autenticación
    # -------------------------
    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="auth/login.html",
            extra_context={"hide_register_link": True},  # para ocultar el botón en el header
        ),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(next_page="home_publico"), name="logout"),
    path("redirigir/", views.redirigir_segun_rol, name="redirigir_segun_rol"),
    # -------------------------
    # Registro y perfil
    # -------------------------
    path("registro/", views.registro, name="registro"),
    path("mi-perfil/", views.mi_perfil, name="mi_perfil"),
    path("editar-perfil/", views.editar_perfil, name="editar_perfil"),
   #NUEVAS PARA PACIENTES CONTROL 
    path("pacientes/<int:perfil_id>/perfil/", views.perfil_paciente, name="perfil_paciente"),
    path("pacientes/<int:perfil_id>/historia/", views.historia_paciente, name="historia_paciente"),
    path("pacientes/<int:perfil_id>/nuevo-signo/", views.nuevo_signo, name="nuevo_signo"),
    # -------------------------
    # Roles y permisos
    # -------------------------
    path("lista-perfiles/", views.lista_perfiles, name="lista_perfiles"),
    path("admin-dashboard/", views.panel_admin, name="panel_admin"),
    path("doctor-dashboard/", views.panel_doctor, name="panel_doctor"),
    path("paciente-dashboard/", views.panel_paciente, name="panel_paciente"),
    path("asignar-roles/", views.asignar_roles, name="asignar_roles"),
    # ... tus rutas ...
    path("lista-usuarios/", views.lista_usuarios, name="lista_usuarios"),
    path("usuarios/<int:user_id>/toggle-activo/", views.toggle_activo, name="toggle_activo"),
    path("usuarios/exportar-csv/", views.exportar_usuarios_csv, name="exportar_usuarios_csv"),
    path("mi-cuenta/", views.editar_cuenta, name="editar_cuenta"),
    path("registro-paciente/", views.registro_paciente, name="registro_paciente"),

    # -------------------------
    # Redirección automática según rol
    # -------------------------
    path("redirigir/", views.redirigir_segun_rol, name="redirigir_segun_rol"),
    # cambio de contraseñas doctores 
    path(
        "password-change/",
        auth_views.PasswordChangeView.as_view(
            template_name="auth/password_change_form.html",
            success_url="/password-change/done/"
        ),
        name="password_change",
        ),
        path(
        "password-change/done/",
        auth_views.PasswordChangeDoneView.as_view(
            template_name="auth/password_change_done.html"
        ),
        name="password_change_done",
        ),
    # olvide la contraseña 
    path(
    "password-reset/",
    auth_views.PasswordResetView.as_view(
        template_name="auth/password_reset_form.html",
        email_template_name="auth/password_reset_email.txt",
        subject_template_name="auth/password_reset_subject.txt",
        success_url="/password-reset/done/"
    ),
    name="password_reset",
    ),
    path(
    "password-reset/done/",
    auth_views.PasswordResetDoneView.as_view(template_name="auth/password_reset_done.html"),
    name="password_reset_done",
    ),
    path(
    "reset/<uidb64>/<token>/",
    auth_views.PasswordResetConfirmView.as_view(
        template_name="auth/password_reset_confirm.html",
        success_url="/reset/done/"
    ),
    name="password_reset_confirm",
    ),
    path(
    "reset/done/",
    auth_views.PasswordResetCompleteView.as_view(template_name="auth/password_reset_complete.html"),
    name="password_reset_complete",
    ),

    # -------------------------
    # CRUD de Signos Vitales
    # -------------------------
     path("signos-vitales/", views.signos_vitales, name="signos_vitales"),
    path("listado-signos-vitales/", views.listado_signos_vitales, name="listado_signos_vitales"),
    path("nuevo-signo-vital/", views.guardar_signos_vitales, name="nuevo_signo_vital"),
    path("editar-signo-vital/<int:id>/", views.editar_signo_vital, name="editar_signo_vital"),
    path("eliminar-signo-vital/<int:id>/", views.eliminar_signo_vital, name="eliminar_signo_vital"),

    # -------------------------
    # SEGUNDA PARTE DE LA BDD
    # -------------------------

     # CIE-10
    path('cie10', views.cie10_inicio, name='cie10_inicio'),
    path('listado/', views.cie10_listado, name='cie10_listado'),
    path('formulario/', views.cie10_formulario, name='cie10_formulario'),
    path('guardar/', views.cie10_guardar, name='cie10_guardar'),
    path('eliminar/', views.cie10_eliminar, name='cie10_eliminar'),
    # Historia Clínica
     path('historiaclinica/', views.inicio_historiaclinica, name='inicio'),
    
    # Endpoints AJAX que usa inicio.html
    path('ajax/listado/', views.listado_historias, name='ajax_listado'),
    path('ajax/formulario/', views.obtener_formulario, name='ajax_formulario'),
    path('ajax/guardar/', views.guardar_historia, name='ajax_guardar'),
    path('ajax/detalle/<int:id>/', views.detalle_historia, name='ajax_detalle'),
    path('ajax/eliminar/', views.eliminar_historia, name='ajax_eliminar'),
    path('ajax/pacientes/', views.buscar_pacientes, name='ajax_pacientes'),
    path('ajax/expediente/', views.generar_expediente, name='ajax_expediente'),
    path('ajax/cie10/', views.buscar_cie10, name='ajax_cie10'),
    

]
