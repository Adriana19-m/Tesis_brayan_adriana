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
    path("cie10/", views.cie10_index, name="cie10_index"),
    path("cie10/listar/", views.cie10_listar, name="cie10_listar"),
    path("cie10/formulario/", views.cie10_formulario, name="cie10_formulario"),
    path("cie10/guardar/", views.cie10_guardar, name="cie10_guardar"),
    path("cie10/eliminar/", views.cie10_eliminar, name="cie10_eliminar"),

    # Historia clínica
    path("historia/", views.historia_index, name="historia_index"),
    path("historia/listar/", views.historia_listar, name="historia_listar"),
    path("historia/formulario/", views.historia_formulario, name="historia_formulario"),
    path("historia/guardar/", views.historia_guardar, name="historia_guardar"),
    path("historia/eliminar/", views.historia_eliminar, name="historia_eliminar"),

    # Historia-CIE10
    path("historia_cie10/", views.historia_cie10_index, name="historia_cie10_index"),
    path("historia_cie10/listar/", views.historia_cie10_listar, name="historia_cie10_listar"),
    path("historia_cie10/formulario/", views.historia_cie10_formulario, name="historia_cie10_formulario"),
    path("historia_cie10/guardar/", views.historia_cie10_guardar, name="historia_cie10_guardar"),
    path("historia_cie10/eliminar/", views.historia_cie10_eliminar, name="historia_cie10_eliminar"),

    # Cita
    path("cita/", views.cita_index, name="cita_index"),
    path("cita/listar/", views.cita_listar, name="cita_listar"),
    path("cita/formulario/", views.cita_formulario, name="cita_formulario"),
    path("cita/guardar/", views.cita_guardar, name="cita_guardar"),
    path("cita/eliminar/", views.cita_eliminar, name="cita_eliminar"),

    # Archivo de cita
    path("archivo_cita/", views.archivo_cita_index, name="archivo_cita_index"),
    path("archivo_cita/listar/", views.archivo_cita_listar, name="archivo_cita_listar"),
    path("archivo_cita/formulario/", views.archivo_cita_formulario, name="archivo_cita_formulario"),
    path("archivo_cita/guardar/", views.archivo_cita_guardar, name="archivo_cita_guardar"),
    path("archivo_cita/eliminar/", views.archivo_cita_eliminar, name="archivo_cita_eliminar"),

    # Encuesta de cita
    path("encuesta_cita/", views.encuesta_cita_index, name="encuesta_cita_index"),
    path("encuesta_cita/listar/", views.encuesta_cita_listar, name="encuesta_cita_listar"),
    path("encuesta_cita/formulario/", views.encuesta_cita_formulario, name="encuesta_cita_formulario"),
    path("encuesta_cita/guardar/", views.encuesta_cita_guardar, name="encuesta_cita_guardar"),
    path("encuesta_cita/eliminar/", views.encuesta_cita_eliminar, name="encuesta_cita_eliminar"),

    # Atención
    path("atencion/", views.atencion_index, name="atencion_index"),
    path("atencion/listar/", views.atencion_listar, name="atencion_listar"),
    path("atencion/formulario/", views.atencion_formulario, name="atencion_formulario"),
    path("atencion/guardar/", views.atencion_guardar, name="atencion_guardar"),
    path("atencion/eliminar/", views.atencion_eliminar, name="atencion_eliminar"),

    # Atención-CIE10
    path("atencion_cie10/", views.atencion_cie10_index, name="atencion_cie10_index"),
    path("atencion_cie10/listar/", views.atencion_cie10_listar, name="atencion_cie10_listar"),
    path("atencion_cie10/formulario/", views.atencion_cie10_formulario, name="atencion_cie10_formulario"),
    path("atencion_cie10/guardar/", views.atencion_cie10_guardar, name="atencion_cie10_guardar"),
    path("atencion_cie10/eliminar/", views.atencion_cie10_eliminar, name="atencion_cie10_eliminar"),

    # Revisión por sistemas
    path("revision/", views.revision_index, name="revision_index"),
    path("revision/formulario/", views.revision_formulario, name="revision_formulario"),
    path("revision/guardar/", views.revision_guardar, name="revision_guardar"),

    # Examen físico
    path("examen/", views.examen_index, name="examen_index"),
    path("examen/formulario/", views.examen_formulario, name="examen_formulario"),
    path("examen/guardar/", views.examen_guardar, name="examen_guardar"),

    # Notificación
    path("notificacion/", views.notificacion_index, name="notificacion_index"),
    path("notificacion/listar/", views.notificacion_listar, name="notificacion_listar"),
    path("notificacion/formulario/", views.notificacion_formulario, name="notificacion_formulario"),
    path("notificacion/guardar/", views.notificacion_guardar, name="notificacion_guardar"),
    path("notificacion/eliminar/", views.notificacion_eliminar, name="notificacion_eliminar"),

    # Horario doctor
path("horario/", views.horario_index, name="horario_index"),
path("horario/listar/", views.horario_listar, name="horario_listar"),
path("horario/formulario/", views.horario_formulario, name="horario_formulario"),
path("horario/guardar/", views.horario_guardar, name="horario_guardar"),
path("horario/eliminar/", views.horario_eliminar, name="horario_eliminar"),
path("horario/calendario/", views.horario_calendario, name="horario_calendario"),
path("horario/eventos/", views.horario_eventos, name="horario_eventos"),
path("horario/disponibilidad/", views.horario_disponibilidad, name="horario_disponibilidad"),

    # Archivo de atención
    path("archivo_atencion/", views.archivo_atencion_index, name="archivo_atencion_index"),
    path("archivo_atencion/listar/", views.archivo_atencion_listar, name="archivo_atencion_listar"),
    path("archivo_atencion/formulario/", views.archivo_atencion_formulario, name="archivo_atencion_formulario"),
    path("archivo_atencion/guardar/", views.archivo_atencion_guardar, name="archivo_atencion_guardar"),
    path("archivo_atencion/eliminar/", views.archivo_atencion_eliminar, name="archivo_atencion_eliminar"),

]
