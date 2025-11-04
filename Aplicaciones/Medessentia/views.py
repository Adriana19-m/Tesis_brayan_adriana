import re
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.contrib import messages
from .models import PerfilUsuario, SignosVitales
from decimal import Decimal
from django.http import JsonResponse
from django.utils.dateparse import parse_datetime
from django.db import IntegrityError, transaction
from django.db.models import Prefetch
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.views.decorators.http import require_POST
from django.core.exceptions import MultipleObjectsReturned
from datetime import timedelta
from django.utils import timezone
from django.db.models import Max, Q, Case, When, Value, IntegerField
from decimal import Decimal, InvalidOperation

def home_publico(request):
    """Landing pública con Medilab."""
    return render(request, "public/index.html")

# ---------------------------------
# Helper: verificación de Administrador
# ---------------------------------
def es_admin(user):
    """Devuelve True si es superusuario o pertenece al grupo 'Administrador'."""
    return user.is_superuser or user.groups.filter(name="Administrador").exists()

# ---------------------------------
# Utilidad: garantizar perfil
# ---------------------------------
def ensure_perfil(user):
    """
    Devuelve un (único) PerfilUsuario para el user.
    - Si no existe, lo crea con placeholders válidos.
    - Si hay duplicados, conserva uno, fusiona datos básicos y elimina el resto.
    """
    try:
        return user.perfil  # si el campo es OneToOne y no hay duplicados
    except PerfilUsuario.DoesNotExist:
        with transaction.atomic():
            return PerfilUsuario.objects.create(
                user=user,
                genero_usuario=None,
                cedula_usuario="0000000000",
                telefono_usuario="0000000000",
                direccion_usuario="",
            )
    except (MultipleObjectsReturned, PerfilUsuario.MultipleObjectsReturned):
        # Hay más de un perfil para este user
        with transaction.atomic():
            perfiles = list(PerfilUsuario.objects.filter(user=user).order_by('id'))
            keeper = perfiles[0]
            extras = perfiles[1:]

            # Fusión simple de datos (si el keeper tiene placeholders)
            for dup in extras:
                if (not keeper.direccion_usuario) and dup.direccion_usuario:
                    keeper.direccion_usuario = dup.direccion_usuario
                if (not keeper.genero_usuario) and dup.genero_usuario:
                    keeper.genero_usuario = dup.genero_usuario
                if keeper.cedula_usuario in (None, "", "0000000000") and dup.cedula_usuario not in (None, "", "0000000000"):
                    keeper.cedula_usuario = dup.cedula_usuario
                if keeper.telefono_usuario in (None, "", "0000000000") and dup.telefono_usuario not in (None, "", "0000000000"):
                    keeper.telefono_usuario = dup.telefono_usuario
            keeper.save(update_fields=["direccion_usuario","genero_usuario","cedula_usuario","telefono_usuario"])

            # Borra los duplicados
            PerfilUsuario.objects.filter(id__in=[d.id for d in extras]).delete()
            return keeper
# -------------------------
# PERFIL DE USUARIO
# -------------------------
@login_required
def mi_perfil(request):
    perfil = ensure_perfil(request.user)
    return render(request, "public/mi_perfil.html", {"perfil": perfil})
@login_required
def editar_perfil(request):
    perfil = ensure_perfil(request.user)

    if request.method == "POST":
        ced = (request.POST.get("cedula_usuario") or "").strip()
        tel = (request.POST.get("telefono_usuario") or "").strip()

        if not (ced.isdigit() and len(ced) == 10):
            messages.error(request, "La cédula debe tener 10 dígitos (sin guiones).")
            return redirect("editar_perfil")

        # Permite dejarlo vacío, pero guardamos 0000000000 para cumplir NOT NULL
        if tel and not (tel.isdigit() and len(tel) == 10):
            messages.error(request, "El teléfono debe tener 10 dígitos.")
            return redirect("editar_perfil")
        if not tel:
            tel = "0000000000"

        perfil.genero_usuario   = (request.POST.get("genero_usuario") or "").strip() or None
        perfil.cedula_usuario   = ced
        perfil.telefono_usuario = tel                        # <- nunca None
        perfil.direccion_usuario = (request.POST.get("direccion_usuario") or "").strip()
        perfil.save()

        messages.success(request, "Perfil actualizado correctamente.")
        return redirect("mi_perfil")

    return render(request, "public/editar_perfil.html", {"perfil": perfil})

# -------------------------
# REGISTRO DE USUARIO (solo Admin)
def _sanear_telefono(valor):
    """
    Devuelve SIEMPRE 10 dígitos.
    - Si viene vacío o None -> '0000000000'
    - Si trae menos/más dígitos -> recorta/ajusta a 10
    """
    dig = "".join(ch for ch in str(valor or "") if ch.isdigit())
    if not dig:
        dig = "0000000000"
    if len(dig) < 10:
        dig = (dig + "0000000000")[:10]
    else:
        dig = dig[:10]
    return dig
# -------------------------
@user_passes_test(es_admin)
def registro(request):
    if request.method == "POST":
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password   = (request.POST.get("password") or "")
        cedula     = (request.POST.get("cedula_usuario") or "").strip()

        # Teléfono: jamás NULL
        telefono_final = _sanear_telefono(request.POST.get("telefono_usuario"))

        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = (request.POST.get("genero_usuario") or "").strip() or None
        auto_paciente = request.POST.get("asignar_paciente") == "on"

        # Validaciones mínimas
        errores = []
        if not username:
            errores.append("Debes ingresar un nombre de usuario.")
        if not email:
            errores.append("Debes ingresar un correo.")
        if not password or len(password) < 8:
            errores.append("La contraseña debe tener al menos 8 caracteres.")
        if not (cedula.isdigit() and len(cedula) == 10):
            errores.append("La cédula debe tener 10 dígitos.")
        # Si el admin escribió algo en el campo, valida 10 dígitos
        if request.POST.get("telefono_usuario"):
            if len("".join(ch for ch in request.POST.get("telefono_usuario") if ch.isdigit())) != 10:
                errores.append("El teléfono debe tener 10 dígitos.")

        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "admingen/registro.html", {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": request.POST.get("telefono_usuario", ""),
                    "direccion_usuario": direccion,
                    "genero_usuario": (genero or ""),
                    "asignar_paciente": auto_paciente,
                }
            })

        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            PerfilUsuario.objects.create(
                user=user,
                genero_usuario=genero,
                cedula_usuario=cedula,
                telefono_usuario=telefono_final,  # <- NUNCA NULL
                direccion_usuario=direccion,
            )
            if auto_paciente:
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

        messages.success(request, f"Usuario {username} creado correctamente.")
        return redirect("lista_usuarios")

    return render(request, "admingen/registro.html")
#------Perfil editar doctor 
# views.py
@login_required
def editar_cuenta(request):
    user = request.user
    if request.method == "POST":
        user.first_name = (request.POST.get("first_name") or "").strip()
        user.last_name  = (request.POST.get("last_name") or "").strip()
        user.email      = (request.POST.get("email") or "").strip()
        user.save()
        messages.success(request, "Datos de cuenta actualizados.")
        return redirect("editar_cuenta")
    return render(request, "cuenta/editar_cuenta.html", {"user": user})

#-----
@login_required
@user_passes_test(es_admin)
def lista_usuarios(request):
    """
    Admin: lista con filtros (rol, activo), búsqueda, orden y paginación.
    Incluye KPIs por rol y estado.
    """
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()  # "activo", "inactivo" o ""
    q = request.GET.get("q", "").strip()
    order = request.GET.get("order", "date_joined_desc")  # opciones: username, date_joined_asc, _desc, last_login_...

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")

    if rol:
        qs = qs.filter(groups__name=rol)

    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)

    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        )

    order_map = {
        "username_asc": "username",
        "username_desc": "-username",
        "date_joined_asc": "date_joined",
        "date_joined_desc": "-date_joined",
        "last_login_asc": "last_login",
        "last_login_desc": "-last_login",
    }
    qs = qs.order_by(order_map.get(order, "-date_joined")).distinct()

    # KPIs (conteos)
    kpis = {
        "total": User.objects.count(),
        "activos": User.objects.filter(is_active=True).count(),
        "inactivos": User.objects.filter(is_active=False).count(),
        "por_rol": dict(
            User.objects.values("groups__name")
            .annotate(n=Count("id"))
            .values_list("groups__name", "n")
        ),
    }

    paginator = Paginator(qs, 12)  # 12 por página
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "admingen/lista_usuarios.html", {
        "usuarios": page_obj.object_list,
        "page_obj": page_obj,
        "rol": rol,
        "estado": estado,
        "q": q,
        "order": order,
        "kpis": kpis,
    })
#----- activar y desactivar 
@require_POST
@login_required
@user_passes_test(es_admin)
def toggle_activo(request, user_id):
    if int(user_id) == request.user.id:
        messages.error(request, "No puedes desactivarte a ti mismo.")
        return redirect("lista_usuarios")

    u = get_object_or_404(User, id=user_id)
    u.is_active = not u.is_active
    u.save(update_fields=["is_active"])
    estado = "activado" if u.is_active else "desactivado"
    messages.success(request, f"Usuario '{u.username}' {estado}.")
    return redirect(request.META.get("HTTP_REFERER", "lista_usuarios"))
# _____ usuariios csv
@login_required
@user_passes_test(es_admin)
def exportar_usuarios_csv(request):
    import csv
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="usuarios.csv"'
    writer = csv.writer(response)

    # Reutiliza filtros básicos
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()
    q = request.GET.get("q", "").strip()

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")
    if rol:
        qs = qs.filter(groups__name=rol)
    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)
    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        ).distinct()

    writer.writerow([
        "username","first_name","last_name","email","roles",
        "is_active","last_login","date_joined",
        "genero","cedula","telefono","direccion","fecha_registro_perfil",
    ])

    for u in qs:
        roles = ", ".join(g.name for g in u.groups.all()) or "—"
        p = getattr(u, "perfil", None)
        writer.writerow([
            u.username, u.first_name, u.last_name, u.email, roles,
            "activo" if u.is_active else "inactivo",
            u.last_login or "", u.date_joined or "",
            getattr(p, "genero_usuario", "") or "—",
            getattr(p, "cedula_usuario", "") or "—",
            getattr(p, "telefono_usuario", "") or "—",
            getattr(p, "direccion_usuario", "") or "—",
            getattr(p, "fecha_registro_usuario", "") or "",
        ])
    return response

# -------------------------
# VISTAS CON ROLES/PERMISOS
# -------------------------
@login_required
@permission_required("Medessentia.view_perfilusuario", raise_exception=True)
def lista_perfiles(request):
    perfiles = PerfilUsuario.objects.all()
    return render(request, "lista_perfiles.html", {"perfiles": perfiles})


@login_required
@user_passes_test(es_admin)
def panel_admin(request):
    # Tu estructura real: Templates/admingen/admin_dashboard.html
    return render(request, "dashboards/panel_admin.html")



@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def panel_doctor(request):
    """ Panel exclusivo para los doctores """
    signos = SignosVitales.objects.all()
    # Tienes Templates/panel_doctor.html (sin subcarpeta)
    return render(request, "dashboards/panel_doctor.html")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Paciente").exists())
def panel_paciente(request):
    perfil = ensure_perfil(request.user)

    # Si sigue con placeholders, mándalo a completar el perfil
    if perfil.cedula_usuario == "0000000000" or perfil.telefono_usuario == "0000000000":
        messages.warning(request, "Completa tu perfil antes de continuar.")
        return redirect("editar_perfil")

    signos = perfil.signos_vitales.all()
    return render(request, "public/panel_paciente.html", {"perfil": perfil, "signos": signos})
# ------tener en cuenta formulario para pacientes
@require_http_methods(["GET", "POST"])
def registro_paciente(request):
    # No permitir registrarse si ya está logueado
    if request.user.is_authenticated:
        messages.info(request, "Ya has iniciado sesión.")
        return redirect("redirigir_segun_rol")

    if request.method == "POST":
        # --- Capturar datos del formulario (sin forms.py) ---
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password1  = request.POST.get("password1") or ""
        password2  = request.POST.get("password2") or ""
        cedula     = (request.POST.get("cedula_usuario") or "").strip()
        telefono   = (request.POST.get("telefono_usuario") or "").strip()
        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = request.POST.get("genero_usuario") or None

        # --- Validaciones básicas ---
        errores = []
        if not username:
            errores.append("El usuario es obligatorio.")
        if not email:
            errores.append("El correo es obligatorio.")
        if password1 != password2:
            errores.append("Las contraseñas no coinciden.")
        if len(cedula) != 10 or not cedula.isdigit():
            errores.append("La cédula debe tener 10 dígitos numéricos.")
        if telefono and (len(telefono) != 10 or not telefono.isdigit()):
            errores.append("El teléfono debe tener 10 dígitos numéricos.")

        # Unicidad
        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            # Re-render con lo que el usuario escribió
            context = {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": telefono,
                    "direccion_usuario": direccion,
                    "genero_usuario": genero or "",
                }
            }
            return render(request, "auth/registro_paciente.html", context)

        # --- Crear usuario + perfil + asignar grupo Paciente ---
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1,
                    first_name=first_name,
                    last_name=last_name,
                )
                # asegurar grupo
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

                PerfilUsuario.objects.create(
                    user=user,
                    genero_usuario=genero,
                    cedula_usuario=cedula,        # tu validador de modelo validará la cédula
                    telefono_usuario=_sanear_telefono(telefono), 
                    direccion_usuario=direccion or "",
                )
        except Exception as e:
            messages.error(request, f"Ocurrió un error creando la cuenta: {e}")
            return render(request, "auth/registro_paciente.html", {"prefill": request.POST})

        # Login inmediato y redirección a su panel
        login(request, user)
        messages.success(request, "¡Cuenta creada correctamente! Bienvenido/a.")
        return redirect("redirigir_segun_rol")

    # GET
    return render(request, "auth/registro_paciente.html")
# -------------------------
# REDIRECCIÓN SEGÚN ROL
# -------------------------
@login_required
def redirigir_segun_rol(request):
    user = request.user
    if user.groups.filter(name="Administrador").exists():
        return redirect("panel_admin")
    elif user.groups.filter(name="Doctor").exists():
        return redirect("panel_doctor")
    elif user.groups.filter(name="Paciente").exists():
        return redirect("panel_paciente")
    else:
        messages.error(request, "No tienes un rol asignado. Contacta con el administrador.")
        return redirect("mi_perfil")
#------perfil del doctor administar pacientes 
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    hoy = timezone.now()
    qs = (PerfilUsuario.objects
          .filter(user__groups__name="Paciente")
          .select_related("user")
          .annotate(
              ultimo_control=Max("signos_vitales__fecha_registro")
          ))

    # Calcular “estado_control” por días desde último control
    # 0=sin datos, 1=ok (<30d), 2=pronto (30–59d), 3=vencido (>=60d)
    treinta = hoy - timedelta(days=30)
    sesenta = hoy - timedelta(days=60)
    qs = qs.annotate(
        estado_control=Case(
            When(ultimo_control__isnull=True, then=Value(0)),
            When(ultimo_control__gte=treinta, then=Value(1)),
            When(ultimo_control__lt=treinta, ultimo_control__gte=sesenta, then=Value(2)),
            default=Value(3),
            output_field=IntegerField()
        )
    )

    # Búsqueda servidor (opcional)
    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(user__first_name__icontains=q) |
            Q(user__last_name__icontains=q) |
            Q(user__username__icontains=q) |
            Q(cedulaUsuario__icontains=q) |
            Q(telefono_usuario__icontains=q)
        )

    # Orden
    order = request.GET.get("order") or "-ultimo_control"
    qs = qs.order_by(order, "user__username")

    # KPIs
    total = qs.count()
    con_datos = qs.filter(ultimo_control__isnull=False)
    kpis = {
        "total": total,
        "ok": con_datos.filter(ultimo_control__gte=treinta).count(),
        "pronto": con_datos.filter(ultimo_control__lt=treinta, ultimo_control__gte=sesenta).count(),
        "vencido": con_datos.filter(ultimo_control__lt=sesenta).count(),
        "sindatos": qs.filter(ultimo_control__isnull=True).count(),
    }

    paginator = Paginator(qs, 12)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "doctor/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })
# ----------- PARA PACIENTES 
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    ...
    return render(request, "pacientes/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })

@login_required
def historia_paciente(request, perfil_id):
    """Detalle simple de historia: lista de signos vitales del paciente."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    signos = perfil.signos_vitales.all().order_by("-fecha_registro")
    return render(request, "doctor/historia_paciente.html", {
        "perfil": perfil,
        "signos": signos,
    })

@login_required
def nuevo_signo(request, perfil_id):
    """
    Placeholder: aquí podrías mostrar un formulario para agregar signos.
    De momento, solo redirige a la historia con un mensaje.
    """
    get_object_or_404(PerfilUsuario, id=perfil_id)
    messages.info(request, "Formulario de 'Añadir signos' aún no implementado.")
    return redirect("historia_paciente", perfil_id=perfil_id)

@login_required
def perfil_paciente(request, perfil_id):
    """Ficha rápida del paciente (datos del perfil)."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    return render(request, "doctor/perfil_paciente.html", {
        "perfil": perfil,
    })
# -------------------------
# ASIGNAR ROLES (rol único)
# -------------------------
@login_required
@user_passes_test(es_admin)
def asignar_roles(request):
    usuarios = User.objects.all().order_by("username")
    grupos = Group.objects.all().order_by("name")

    if request.method == "POST":
        usuario_id = request.POST.get("usuario_id")
        rol = request.POST.get("rol")
        if usuario_id and rol:
            usuario = get_object_or_404(User, id=usuario_id)
            grupo = get_object_or_404(Group, name=rol)
            usuario.groups.clear()
            usuario.groups.add(grupo)
            messages.success(request, f"Rol '{rol}' asignado a {usuario.username}")
            return redirect("asignar_roles")

    # Tu estructura real: Templates/admingen/asignar_roles.html
    return render(request, "admingen/asignar_roles.html", {"usuarios": usuarios, "grupos": grupos})

@login_required
def lista_perfiles(request):
    """
    - Admin: ve todos los perfiles.
    - Doctor: ve SOLO perfiles cuyos usuarios estén en el grupo 'Paciente'.
    - Paciente: (opcional) solo ve su propio perfil.
    """
    qs = PerfilUsuario.objects.select_related("user")

    if request.user.groups.filter(name="Doctor").exists():
        qs = qs.filter(user__groups__name="Paciente").distinct()
        solo_pacientes = True
    elif request.user.groups.filter(name="Paciente").exists():
        qs = qs.filter(user=request.user)
        solo_pacientes = False
    else:
        # Admin u otros con permisos
        solo_pacientes = False

    perfiles = qs.order_by("user__username")
    return render(request, "lista_perfiles.html", {
        "perfiles": perfiles,
        "solo_pacientes": solo_pacientes,
    })
# -------------------------
# SIGNOS VITALES
# -------------------------
def es_doctor_o_admin(u):
    return u.is_authenticated and (u.groups.filter(name="Doctor").exists() or es_admin(u))

@login_required
@user_passes_test(es_doctor_o_admin)
def nuevo_signo(request, perfil_id):
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)

    if request.method == "POST":
        # --- Captura segura ---
        fecha_raw = (request.POST.get("fecha_registro") or "").strip()

        # Presión arterial desglosada
        pas_raw = (request.POST.get("pa_sistolica") or "").strip()
        pad_raw = (request.POST.get("pa_diastolica") or "").strip()
        pam_raw = (request.POST.get("pa_media") or "").strip()

        # Signos vitales
        temp_raw = (request.POST.get("temperatura") or "").strip()
        fr_raw   = (request.POST.get("frecuencia_respiratoria") or "").strip()
        fc_raw   = (request.POST.get("frecuencia_cardiaca") or "").strip()
        spo2_raw = (request.POST.get("saturacion_oxigeno") or "").strip()

        # Antropometría
        peso_raw  = (request.POST.get("peso") or "").strip()
        talla_raw = (request.POST.get("talla") or "").strip()
        imc_raw   = (request.POST.get("imc") or "").strip()

        # Capilares
        glucosa_raw    = (request.POST.get("glucosa_capilar") or "").strip()
        hemoglobina_raw = (request.POST.get("hemoglobina") or "").strip()

        obs = (request.POST.get("observaciones") or "").strip()

        errores = []

        # Fecha/hora
        fecha_registro = parse_datetime(fecha_raw) if fecha_raw else timezone.now()
        if fecha_raw and not fecha_registro:
            errores.append("Fecha inválida. Usa el formato YYYY-MM-DD HH:MM.")

        # Enteros
        def to_int(name, raw, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                return int(raw)
            except ValueError:
                errores.append(f"{name} debe ser un número entero.")
                return None

        # Decimales
        def to_dec(name, raw, ndigits=None, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                d = Decimal(raw)
                return d if ndigits is None else d.quantize(Decimal(ndigits))
            except (InvalidOperation, ValueError):
                errores.append(f"{name} debe ser un número válido.")
                return None

        # PAS/PAD/PAM
        pas = to_int("Presión sistólica (PAS)", pas_raw, obligatorio=False)
        pad = to_int("Presión diastólica (PAD)", pad_raw, obligatorio=False)
        pam = to_dec("Presión arterial media (PAM)", pam_raw, "0.01", obligatorio=False)

        # Vitals
        fc  = to_int("Frecuencia cardiaca", fc_raw, obligatorio=True)
        fr  = to_int("Frecuencia respiratoria", fr_raw, obligatorio=True)
        spo2 = to_int("Saturación de oxígeno", spo2_raw, obligatorio=True)
        temp = to_dec("Temperatura", temp_raw, "0.1", obligatorio=True)

        # Antropometría
        peso  = to_dec("Peso",  peso_raw,  "0.01", obligatorio=True)
        talla = to_dec("Talla", talla_raw, "0.01", obligatorio=True)
        imc   = to_dec("IMC",   imc_raw,   "0.01", obligatorio=False)

        # Capilares
        glucosa     = to_dec("Glucosa capilar", glucosa_raw, "0.1", obligatorio=False)
        hemoglobina = to_dec("Hemoglobina",     hemoglobina_raw, "0.1", obligatorio=False)

        # Reglas sanidad
        if temp is not None and not (Decimal("30.0") <= temp <= Decimal("45.0")):
            errores.append("Temperatura fuera de rango razonable (30.0 – 45.0 °C).")
        if spo2 is not None and not (50 <= spo2 <= 100):
            errores.append("SpO₂ debe estar entre 50 y 100.")
        if peso is not None and peso <= 0:
            errores.append("El peso debe ser > 0.")
        if talla is not None and talla <= 0:
            errores.append("La talla debe ser > 0.")

        # Calcular PAM si no viene pero sí hay PAS/PAD
        if pam is None and (pas is not None and pad is not None):
            pam = (Decimal(2) * Decimal(pad) + Decimal(pas)) / Decimal(3)
            pam = pam.quantize(Decimal("0.01"))

        # Calcular IMC si no viene y hay peso/talla
        if imc is None and (peso is not None and talla is not None and talla > 0):
            imc = (peso / (talla * talla)).quantize(Decimal("0.01"))

        # Para compatibilidad, construimos presion_arterial "120/80" si hay PAS/PAD
        presion_compuesta = ""
        if pas is not None and pad is not None:
            presion_compuesta = f"{pas}/{pad}"

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "doctor/nuevo_signo.html", {
                "perfil": perfil,
                "prefill": {
                    "fecha_registro": fecha_raw,
                    "pa_sistolica": pas_raw,
                    "pa_diastolica": pad_raw,
                    "pa_media": pam_raw or (str(pam) if pam is not None else ""),
                    "temperatura": temp_raw,
                    "frecuencia_respiratoria": fr_raw,
                    "frecuencia_cardiaca": fc_raw,
                    "saturacion_oxigeno": spo2_raw,
                    "peso": peso_raw,
                    "talla": talla_raw,
                    "imc": imc_raw or (str(imc) if imc is not None else ""),
                    "glucosa_capilar": glucosa_raw,
                    "hemoglobina": hemoglobina_raw,
                    "observaciones": obs,
                },
            })

        # Crear registro
        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,   # mantiene compatibilidad
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=obs,
            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hemoglobina,
        )

        messages.success(request, "Signos vitales añadidos correctamente.")
        return redirect("historia_paciente", perfil_id=perfil.id)

    # GET inicial
    return render(request, "doctor/nuevo_signo.html", {
        "perfil": perfil,
        "prefill": {
            "fecha_registro": timezone.now().strftime("%Y-%m-%d %H:%M"),
        },
    })
@login_required
def signos_vitales(request):
    """Listado general de signos vitales.
       - Doctor: ve todos
       - Paciente: ve solo los suyos
    """
    if request.user.groups.filter(name="Doctor").exists() or request.user.is_superuser:
        signos = (SignosVitales.objects
                  .select_related("perfil_usuario", "perfil_usuario__user")
                  .order_by("-fecha_registro"))
    else:
        perfil = ensure_perfil(request.user)
        signos = (perfil.signos_vitales
                  .select_related("perfil_usuario__user")
                  .order_by("-fecha_registro"))
    return render(request, "vistasignos/signos_vitales.html", {"signos": signos})


@login_required
def listado_signos_vitales(request):
    """Alias si quieres otra ruta/lista; puedes eliminarla si no la usas."""
    return signos_vitales(request)


@login_required
def guardar_signos_vitales(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Solo se permite POST."})

    perfil = ensure_perfil(request.user)
    try:
        fecha_registro = parse_datetime(request.POST.get("fecha_registro")) or timezone.now()
        fc  = int(request.POST.get("frecuencia_cardiaca", 0))
        fr  = int(request.POST.get("frecuencia_respiratoria", 0))
        temp = Decimal(request.POST.get("temperatura", "0.0"))
        spo2 = int(request.POST.get("saturacion_oxigeno", 0))
        peso = Decimal(request.POST.get("peso", "0.0"))
        talla = Decimal(request.POST.get("talla", "0.0"))
        imc_raw = request.POST.get("imc")
        imc = Decimal(imc_raw) if imc_raw else None

        # nuevos (opcionales)
        pas_raw = request.POST.get("pa_sistolica") or ""
        pad_raw = request.POST.get("pa_diastolica") or ""
        pam_raw = request.POST.get("pa_media") or ""
        gluc_raw = request.POST.get("glucosa_capilar") or ""
        hb_raw   = request.POST.get("hemoglobina") or ""

        pas = int(pas_raw) if pas_raw else None
        pad = int(pad_raw) if pad_raw else None
        pam = Decimal(pam_raw) if pam_raw else None
        glucosa = Decimal(gluc_raw) if gluc_raw else None
        hb = Decimal(hb_raw) if hb_raw else None

        presion_compuesta = f"{pas}/{pad}" if (pas is not None and pad is not None) else ""

        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=request.POST.get("observaciones",""),

            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hb,
        )
        return JsonResponse({"success": True, "message": "Signos vitales guardados correctamente."})
    except Exception as e:
        return JsonResponse({"success": False, "message": f"Error: {e}"})

@login_required
def editar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id

    if request.method == "POST":
        try:
            # ... (tu lógica de actualización)
            signo.save()
            messages.success(request, "Registro actualizado correctamente.")
        except Exception as e:
            messages.error(request, f"Error al actualizar: {e}")
        return redirect("historia_paciente", perfil_id=perfil_id)

    return render(request, "signos_vitales/editar.html", {"signo": signo})

@login_required
def eliminar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id
    signo.delete()
    messages.success(request, "Registro eliminado correctamente.")
    return redirect("historia_paciente", perfil_id=perfil_id)

#-------------SEGUNDA PARTE BDD-------
#-------------------------------------
# tu_app/views.py
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db import transaction, connection
from django.http import JsonResponse
from django.utils import timezone

from .models import (
    Cie10
)

# ---------------- Utilidades JSON ----------------
def ok(data=None, message="OK", status=200):
    return JsonResponse({"ok": True, "message": message, "data": data or {}}, status=status)

def bad(message="Error de validación", data=None, status=400):
    return JsonResponse({"ok": False, "message": message, "data": data or {}}, status=status)

def require(method, request):
    if request.method != method:
        return bad(f"Solo {method}", status=405)
    return None




from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.db.models import Q
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.middleware.csrf import get_token
import json
from .models import Cie10

@login_required
def cie10_inicio(request):
    return render(request, "cie10/inicio.html")

@login_required
def cie10_listado(request):
    try:
        q = request.GET.get("q", "").strip()
        
        queryset = Cie10.objects.all()
        
        if q:
            queryset = queryset.filter(
                Q(codigo__icontains=q) | 
                Q(descripcion__icontains=q)
            )
        
        data = []
        for item in queryset.order_by('codigo'):
            data.append({
                "id_cie10": item.id_cie10,
                "codigo": item.codigo,
                "descripcion": item.descripcion
            })
        
        return JsonResponse({"data": data})
    
    except Exception as e:
        return JsonResponse({"data": [], "error": str(e)})

@login_required
def cie10_formulario(request):
    try:
        item_id = request.GET.get("id")
        item = None
        
        if item_id:
            try:
                item = Cie10.objects.get(id_cie10=item_id)
            except Cie10.DoesNotExist:
                return JsonResponse({"error": "No encontrado"}, status=404)
        
        # Pasar el request para que el CSRF token funcione
        form_html = render_to_string("cie10/formulario.html", {"item": item}, request=request)
        return JsonResponse({"form_html": form_html})
    
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def cie10_guardar(request):
    try:
        # Procesar tanto JSON como FormData
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            codigo = data.get("codigo", "").strip()
            descripcion = data.get("descripcion", "").strip()
            id_cie10 = data.get("id_cie10")
        else:
            # FormData tradicional
            codigo = request.POST.get("codigo", "").strip()
            descripcion = request.POST.get("descripcion", "").strip()
            id_cie10 = request.POST.get("id_cie10")
        
        # Validaciones
        if not codigo:
            return JsonResponse({"success": False, "error": "El código es obligatorio"})
        
        if not descripcion:
            return JsonResponse({"success": False, "error": "La descripción es obligatoria"})
        
        with transaction.atomic():
            if id_cie10:
                # Editar
                item = Cie10.objects.get(id_cie10=id_cie10)
                # Verificar si el código ya existe (excluyendo el actual)
                if Cie10.objects.filter(codigo=codigo).exclude(id_cie10=id_cie10).exists():
                    return JsonResponse({"success": False, "error": "El código ya existe"})
                
                item.codigo = codigo
                item.descripcion = descripcion
                item.save()
                message = "Actualizado correctamente"
            else:
                # Crear
                if Cie10.objects.filter(codigo=codigo).exists():
                    return JsonResponse({"success": False, "error": "El código ya existe"})
                
                item = Cie10.objects.create(codigo=codigo, descripcion=descripcion)
                message = "Creado correctamente"
        
        return JsonResponse({
            "success": True,
            "message": message
        })
        
    except Cie10.DoesNotExist:
        return JsonResponse({"success": False, "error": "Registro no encontrado"})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

@login_required
@require_http_methods(["POST"])
def cie10_eliminar(request):
    try:
        # Procesar tanto JSON como FormData
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            item_id = data.get("id")
        else:
            item_id = request.POST.get("id")
        
        if not item_id:
            return JsonResponse({"success": False, "error": "ID requerido"})
        
        item = Cie10.objects.get(id_cie10=item_id)
        item.delete()
        
        return JsonResponse({"success": True, "message": "Eliminado correctamente"})
        
    except Cie10.DoesNotExist:
        return JsonResponse({"success": False, "error": "Registro no encontrado"})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Q
from django.template.loader import render_to_string
from functools import wraps
import json
from datetime import datetime

from .models import HistoriaClinica, PerfilUsuario, Cie10

# Decorador de permisos integrado
def medicos_only(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        if not request.user.groups.filter(name='Doctor').exists():
            return JsonResponse({'error': 'Solo doctores pueden acceder'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper

# Vista principal - muestra inicio.html
@login_required
def inicio_historiaclinica(request):
    """Vista principal que muestra inicio.html"""
    return render(request, 'historia_clinica/inicio.html')

# AJAX: Listado de historias para la tabla
@medicos_only
@require_http_methods(["GET"])
def listado_historias(request):
    """Obtener listado de historias para DataTable"""
    try:
        search_term = request.GET.get('q', '')
        
        # Usar select_related para optimizar las consultas
        queryset = HistoriaClinica.objects.select_related(
            'id_paciente', 
            'id_doctor'
        ).filter(id_doctor=request.user)
        
        if search_term:
            queryset = queryset.filter(
                Q(id_paciente__first_name__icontains=search_term) |
                Q(id_paciente__last_name__icontains=search_term) |
                Q(expediente_no__icontains=search_term) |
                Q(id_paciente__perfil__cedula_usuario__icontains=search_term)
            )
        
        data = []
        for historia in queryset.order_by('-fecha_elaboracion'):
            try:
                perfil_paciente = historia.id_paciente.perfil
                cedula = perfil_paciente.cedula_usuario
            except (PerfilUsuario.DoesNotExist, AttributeError):
                cedula = 'No registrada'
            
            data.append({
                'id_historia': historia.id_historia,
                'expediente_no': historia.expediente_no,
                'paciente_nombre': f"{historia.id_paciente.first_name} {historia.id_paciente.last_name}",
                'paciente_cedula': cedula,
                'doctor_nombre': f"{historia.id_doctor.first_name} {historia.id_doctor.last_name}",
                'fecha_elaboracion': historia.fecha_elaboracion.strftime('%d/%m/%Y'),
                'edad': historia.edad or '',
                'estado_civil': historia.get_estado_civil_display() if historia.estado_civil else '',
                'puede_editar': True,
                'puede_eliminar': True,
            })
        
        return JsonResponse({
            'data': data,
            'recordsTotal': len(data),
            'recordsFiltered': len(data)
        })
        
    except Exception as e:
        import traceback
        print(f"Error en listado_historias: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Obtener formulario
@medicos_only
@require_http_methods(["GET"])
def obtener_formulario(request):
    """Obtener formulario.html via AJAX"""
    try:
        historia_id = request.GET.get('id')
        historia = None
        
        if historia_id:
            historia = get_object_or_404(
                HistoriaClinica.objects.select_related('id_paciente', 'id_doctor'), 
                id_historia=historia_id, 
                id_doctor=request.user
            )
        
        context = {
            'historia': historia,
            'es_doctor': True,
            'usuario_actual': request.user,
        }
        
        form_html = render_to_string('historia_clinica/formulario.html', context, request=request)
        
        return JsonResponse({'form_html': form_html})
        
    except Exception as e:
        import traceback
        print(f"Error en obtener_formulario: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Guardar historia
@medicos_only
@require_http_methods(["POST"])
def guardar_historia(request):
    """Guardar historia desde formulario.html"""
    try:
        data = json.loads(request.body)
        historia_id = data.get('id_historia')
        
        with transaction.atomic():
            if historia_id:
                # Editar
                historia = get_object_or_404(HistoriaClinica, id_historia=historia_id, id_doctor=request.user)
            else:
                # Crear nueva historia
                historia = HistoriaClinica()
                historia.id_doctor = request.user
                historia.creado_por = request.user
            
            # Campos obligatorios
            historia.expediente_no = data.get('expediente_no')
            historia.fecha_elaboracion = datetime.strptime(data.get('fecha_elaboracion'), '%Y-%m-%d').date()
            
            # Asignar paciente - CORRECTO: asignar el objeto User completo
            paciente_id = data.get('paciente_id')
            if paciente_id:
                paciente = get_object_or_404(User, id=paciente_id)
                historia.id_paciente = paciente
            
            # Campos opcionales
            historia.edad = data.get('edad') or None
            historia.ocupacion = data.get('ocupacion') or None
            historia.estado_civil = data.get('estado_civil') or None
            historia.grupo_sanguineo = data.get('grupo_sanguineo') or 'DESCONOCIDO'
            historia.lugar_nacimiento = data.get('lugar_nacimiento') or None
            historia.alimentacion = data.get('alimentacion') or None
            historia.higiene = data.get('higiene') or None
            historia.inmunizaciones = data.get('inmunizaciones') or None
            historia.quirurgicos = data.get('quirurgicos') or None
            historia.traumaticos = data.get('traumaticos') or None
            historia.transfusionales = data.get('transfusionales') or None
            historia.alergicos = data.get('alergicos') or None
            historia.observaciones = data.get('observaciones') or None
            
            if historia_id:
                historia.actualizado_por = request.user
                historia.fecha_actualizacion = datetime.now()
            
            historia.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Historia clínica guardada exitosamente',
                'id_historia': historia.id_historia
            })
            
    except Exception as e:
        import traceback
        print(f"Error en guardar_historia: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# AJAX: Detalles de historia
@medicos_only
@require_http_methods(["GET"])
def detalle_historia(request, id):
    """Obtener detalles para el modal"""
    try:
        historia = get_object_or_404(
            HistoriaClinica.objects.select_related('id_paciente', 'id_doctor', 'creado_por'), 
            id_historia=id, 
            id_doctor=request.user
        )
        
        try:
            perfil_paciente = historia.id_paciente.perfil
            paciente_telefono = perfil_paciente.telefono_usuario
            paciente_direccion = perfil_paciente.direccion_usuario
            paciente_genero = perfil_paciente.genero_usuario
            paciente_cedula = perfil_paciente.cedula_usuario
        except (PerfilUsuario.DoesNotExist, AttributeError):
            paciente_telefono = 'No especificado'
            paciente_direccion = 'No especificada'
            paciente_genero = 'No especificado'
            paciente_cedula = 'No registrada'
        
        datos = {
            'expediente_no': historia.expediente_no,
            'paciente_nombre': f"{historia.id_paciente.first_name} {historia.id_paciente.last_name}",
            'paciente_cedula': paciente_cedula,
            'paciente_telefono': paciente_telefono,
            'paciente_direccion': paciente_direccion,
            'paciente_genero': paciente_genero,
            'doctor_nombre': f"{historia.id_doctor.first_name} {historia.id_doctor.last_name}",
            'fecha_elaboracion': historia.fecha_elaboracion.strftime('%d/%m/%Y'),
            'edad': historia.edad or 'No especificada',
            'estado_civil': historia.get_estado_civil_display() if historia.estado_civil else 'No especificado',
            'grupo_sanguineo': historia.get_grupo_sanguineo_display() if historia.grupo_sanguineo else 'No especificado',
            'ocupacion': historia.ocupacion or 'No especificada',
            'lugar_nacimiento': historia.lugar_nacimiento or 'No especificado',
            'alimentacion': historia.alimentacion or 'No especificada',
            'higiene': historia.higiene or 'No especificada',
            'inmunizaciones': historia.inmunizaciones or 'No especificadas',
            'quirurgicos': historia.quirurgicos or 'No especificados',
            'traumaticos': historia.traumaticos or 'No especificados',
            'transfusionales': historia.transfusionales or 'No especificados',
            'alergicos': historia.alergicos or 'No especificados',
            'observaciones': historia.observaciones or 'No hay observaciones',
            'creado_por': f"{historia.creado_por.first_name} {historia.creado_por.last_name}",
            'fecha_creacion': historia.fecha_creacion.strftime('%d/%m/%Y %H:%M'),
        }
        
        if historia.actualizado_por:
            datos['actualizado_por'] = f"{historia.actualizado_por.first_name} {historia.actualizado_por.last_name}"
            datos['fecha_actualizacion'] = historia.fecha_actualizacion.strftime('%d/%m/%Y %H:%M')
        
        return JsonResponse({'data': datos})
        
    except Exception as e:
        import traceback
        print(f"Error en detalle_historia: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Eliminar historia
@medicos_only
@require_http_methods(["POST"])
def eliminar_historia(request):
    """Eliminar historia"""
    try:
        data = json.loads(request.body)
        historia_id = data.get('id')
        
        historia = get_object_or_404(HistoriaClinica, id_historia=historia_id, id_doctor=request.user)
        historia.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Historia clínica eliminada exitosamente'
        })
        
    except Exception as e:
        import traceback
        print(f"Error en eliminar_historia: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# AJAX: Buscar pacientes
@medicos_only
@require_http_methods(["GET"])
def buscar_pacientes(request):
    """Buscar pacientes para el formulario"""
    try:
        query = request.GET.get('q', '')
        
        pacientes = PerfilUsuario.objects.select_related('user').all()
        
        if query:
            pacientes = pacientes.filter(
                Q(user__first_name__icontains=query) |
                Q(user__last_name__icontains=query) |
                Q(cedula_usuario__icontains=query)
            )
        
        data = []
        for perfil in pacientes[:20]:
            data.append({
                'id': perfil.user.id,
                'nombre_completo': f"{perfil.user.first_name} {perfil.user.last_name}",
                'cedula': perfil.cedula_usuario,
                'telefono': perfil.telefono_usuario or 'No especificado'
            })
        
        return JsonResponse({'data': data})
        
    except Exception as e:
        import traceback
        print(f"Error en buscar_pacientes: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Generar expediente
@medicos_only
@require_http_methods(["GET"])
def generar_expediente(request):
    """Generar número de expediente automático"""
    try:
        fecha_actual = datetime.now().strftime('%Y%m%d')
        count_hoy = HistoriaClinica.objects.filter(
            fecha_creacion__date=datetime.now().date()
        ).count()
        
        numero = str(count_hoy + 1).zfill(3)
        expediente = f"HC-{fecha_actual}-{numero}"
        
        return JsonResponse({'expediente': expediente})
        
    except Exception as e:
        import traceback
        print(f"Error en generar_expediente: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Buscar CIE-10
@medicos_only
@require_http_methods(["GET"])
def buscar_cie10(request):
    """Buscar códigos CIE-10"""
    try:
        query = request.GET.get('q', '')
        
        if len(query) < 2:
            return JsonResponse({'resultados': []})
        
        resultados = Cie10.objects.filter(
            Q(codigo__icontains=query) | Q(descripcion__icontains=query)
        )[:10]
        
        data = [{
            'codigo': item.codigo,
            'descripcion': item.descripcion
        } for item in resultados]
        
        return JsonResponse({'resultados': data})
    except Exception as e:
        import traceback
        print(f"Error en buscar_cie10: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)