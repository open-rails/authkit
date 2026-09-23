import type { AuthUiMessageBundle } from "../i18n/messages.ts"

export const es: AuthUiMessageBundle = {
  common: {
    continue: "Continuar",
    cancel: "Cancelar",
    back: "Atrás",
    close: "Cerrar",
    confirm: "Confirmar",
    save: "Guardar",
    saving: "Guardando...",
    verify: "Verificar",
    verifying: "Verificando...",
    sending: "Enviando...",
    loading: "Cargando...",
    sendCode: "Enviar código",
    resendCode: "Reenviar código",
    resendIn: "Reenviar código en {seconds}s",
    or: "o",
    orContinueWith: "O continuar con",
    showPassword: "Mostrar contraseña",
    hidePassword: "Ocultar contraseña",
    copy: "Copiar",
    copied: "Copiado",
    download: "Descargar como .txt",
    tryAgain: "Intentar de nuevo",
    goHome: "Ir a la página de inicio",
    verified: "Verificado",
    unverified: "No verificado",
    enabled: "Activado",
    disabled: "Desactivado",
  },
  fields: {
    identifier: "Correo / Teléfono / Usuario",
    emailOrPhone: "Correo o teléfono",
    email: "Correo electrónico",
    emailPlaceholder: "tu@ejemplo.com",
    phone: "Número de teléfono",
    phonePlaceholder: "Introduce el número de teléfono",
    username: "Nombre de usuario",
    usernameOptional: "Nombre de usuario (opcional)",
    password: "Contraseña",
    confirmPassword: "Confirmar contraseña",
    currentPassword: "Contraseña actual",
    currentPasswordPlaceholder: "Ingresa tu contraseña actual",
    newPassword: "Nueva contraseña",
    verificationCode: "Código de verificación",
    codePlaceholder: "Ingresar código",
    generatePassword: "Generar una contraseña segura aleatoria",
  },
  validation: {
    identifierRequired:
      "Ingresa tu correo, número de teléfono o nombre de usuario",
    emailOrPhoneRequired:
      "Introduce tu correo electrónico o número de teléfono",
    emailInvalid: "Ingresa un correo válido",
    phoneInvalid: "Ingresa un número de teléfono válido, p. ej. +1234567890",
    usernameRequired: "Nombre de usuario requerido",
    usernameTooShort:
      "El nombre de usuario debe tener al menos {min} caracteres.",
    usernameTooLong: "El nombre de usuario no puede exceder {max} caracteres.",
    usernameStartWithLetter:
      "El nombre de usuario debe comenzar con una letra.",
    usernameCharacters:
      "El nombre de usuario solo puede contener letras, números y guiones bajos (_).",
    passwordRequired: "Ingresa tu contraseña",
    passwordMinLength: "La contraseña debe tener al menos {min} caracteres",
    passwordNeedsVariety:
      "La contraseña debe incluir una letra mayúscula, una letra minúscula y un número",
    confirmPasswordRequired: "Por favor confirma tu contraseña",
    passwordsDoNotMatch: "Las contraseñas no coinciden",
    newPasswordMustDiffer:
      "La nueva contraseña debe ser diferente de la contraseña actual",
    codeRequired: "Por favor ingresa el código de verificación.",
    codeLength: "Ingresa el código completo de {length} dígitos",
  },
  signIn: {
    tabsLabel: "Inicia sesión o crea una cuenta",
    resetRequiredAction: "Restablecer tu contraseña",
    recovered: "Tu cuenta se ha restaurado. Inicia sesión para continuar.",
    title: "Iniciar sesión",
    titleCombined: "Iniciar sesión / Registrarse",
    description: "Inicia sesión o crea una cuenta para continuar",
    submit: "Iniciar sesión",
    forgotPassword: "¿Olvidaste tu contraseña?",
    noAccount: "¿No tienes una cuenta?",
    createAccount: "Crear cuenta",
    continueWith: "Continuar con {provider}",
    connecting: "Conectando...",
    success: "Sesión iniciada correctamente",
    signedOut: "Sesión cerrada exitosamente",
    sessionExpiredTitle: "Sesión expirada",
    sessionExpiredDescription: "Se cerró tu sesión. Inicia sesión de nuevo.",
    accountUnavailable:
      "Esta cuenta no puede usarse para iniciar sesión. Puede haber sido cerrada o restringida. Si crees que es un error, contacta con soporte.",
  },
  register: {
    passwordHint: "Usa al menos {min} caracteres.",
    complete: "Tu cuenta está lista. Inicia sesión para continuar.",
    title: "Crear cuenta",
    submit: "Registrarse",
    haveAccount: "¿Ya tienes una cuenta?",
    signIn: "Iniciar sesión",
    signUpWith: "Registrarse con {provider}",
    legalPrefix: "Al registrarte, aceptas nuestros",
    terms: "términos de servicio",
    privacy: "política de privacidad",
    and: "y",
    success: "¡Registro exitoso! Por favor revisa tu correo electrónico.",
    phoneUnavailable:
      "El registro por teléfono no está disponible en este momento; regístrate con un correo electrónico en su lugar.",
  },
  verify: {
    cancelBody:
      "Esto elimina tu registro pendiente de {identifier} para que puedas empezar de nuevo.",
    title: "Verifica tu cuenta",
    titleEmail: "Verifica tu correo",
    titlePhone: "Verifica tu teléfono",
    pleaseVerify: "Por favor verifica tu cuenta para continuar.",
    codeSentTo: "Enviamos un código de verificación a {destination}.",
    instructions:
      "Por favor ingresa el código a continuación para completar tu registro.",
    submitEmail: "Verificar correo",
    submitPhone: "Verificar teléfono",
    didntReceive: "¿No recibiste el código?",
    resend: "Reenviar",
    codeSent: "¡Código de verificación enviado! Por favor revisa tus mensajes.",
    verifying: "Verificando...",
    success: "¡Verificado!",
    successDescription:
      "¡Verificado exitosamente! Ahora puedes iniciar sesión.",
    successSignedIn: "¡Verificado e iniciado sesión exitosamente!",
    errorTitle: "Error de verificación",
    emailAlreadyVerifiedTitle:
      "Tu dirección de correo electrónico ya está verificada",
    emailAlreadyVerifiedDescription:
      "El correo electrónico de tu cuenta ya está verificado. Puedes seguir usando tu cuenta.",
    phoneAlreadyVerifiedTitle: "Tu número de teléfono ya está verificado",
    phoneAlreadyVerifiedDescription:
      "El número de teléfono de tu cuenta ya está verificado. Puedes seguir usando tu cuenta.",
    linkExpiredTitle: "Tu enlace de verificación ha caducado",
    emailLinkExpiredDescription:
      "Los enlaces de verificación por correo electrónico caducan después de 60 minutos. Envía otro correo de verificación para continuar.",
    phoneLinkExpiredDescription:
      "Los enlaces de verificación por mensaje de texto caducan después de 15 minutos. Envía otro mensaje de verificación para continuar.",
    invalidLinkTitle: "Enlace de verificación no válido",
    invalidLinkDescription:
      "Este enlace de verificación no es válido. Solicita uno nuevo.",
    sendAgain: "Enviar de nuevo",
    cancelRegistration: "Cancelar registro",
    keepRegistration: "Mantener registro",
    cancelConfirmTitle: "¿Cancelar registro?",
    cancelConfirmDescription:
      "Esto elimina permanentemente tu registro pendiente de {identifier}. Introduce tu contraseña para confirmar.",
    cancelFailed: "No se pudo cancelar el registro.",
  },
  resetPassword: {
    backToSignIn: "Volver a iniciar sesión",
    requestNewLink: "Solicitar un nuevo enlace",
    requestTitle: "Restablecer contraseña",
    requestDescription:
      "Ingresa tu correo o número de teléfono y te enviaremos un enlace para restablecerla.",
    sendLink: "Enviar enlace",
    emailSentTitle: "Revisa tu correo",
    emailSentDescription:
      "Hemos enviado instrucciones para restablecer la contraseña a tu correo. Sigue el enlace para crear una nueva contraseña.",
    smsSentTitle: "Revisa tus mensajes",
    smsSentDescription:
      "Te enviamos instrucciones para restablecer la contraseña a tu teléfono por SMS. Sigue el enlace para establecer una nueva contraseña.",
    title: "Restablecer contraseña",
    instructions:
      "Ingresa el código de verificación enviado a tu correo o teléfono, luego elige una nueva contraseña.",
    submit: "Restablecer contraseña",
    successTitle: "Contraseña restablecida exitosamente",
    successDescription:
      "Tu contraseña se actualizó. Ya puedes iniciar sesión con ella.",
    errorTitle: "Error al restablecer contraseña",
    invalidLink:
      "Este enlace para restablecer la contraseña no es válido o ha caducado. Solicita uno nuevo.",
    required:
      "Tu cuenta es anterior a nuestro nuevo sistema de inicio de sesión. Restablece tu contraseña para continuar.",
  },
  twoFactor: {
    title: "Autenticación en dos pasos",
    challengeTitle: "Confirma que eres tú",
    codePrompt: "Introduce el código 2FA enviado a tu {method}.",
    codePromptTotp:
      "Introduce el código de 6 dígitos de tu aplicación de autenticación.",
    backupPrompt: "Ingresa uno de tus códigos de respaldo para continuar.",
    backupPlaceholder: "Introduce el código de respaldo",
    useBackup: "Usar un código de respaldo",
    useCode: "Usar un código de verificación",
    codeExpires: "Los códigos expiran en {minutes} minutos.",
    enrollmentRequired:
      "Debes configurar la autenticación de dos factores para terminar de iniciar sesión.",
    methods: {
      email: "Correo electrónico",
      sms: "SMS",
      totp: "Aplicación de autenticación",
    },
    hints: {
      email: "Te enviaremos un código a tu correo electrónico.",
      sms: "Te enviaremos un código por SMS.",
      totp: "Genera códigos en una app como Google Authenticator.",
      smsUnavailable: "El envío de SMS no está disponible por ahora.",
    },
    manageTitle: "Gestionar la verificación en dos pasos",
    manageDescription:
      "Activa o desactiva la verificación en dos pasos, o genera nuevos códigos de respaldo.",
    manage: "Gestionar",
    status: "Estado",
    selectMethod: "Método de verificación",
    enable: "Activar 2FA",
    disable: "Desactivar 2FA",
    scanQr:
      "Escanea esto con tu aplicación de autenticación, o toca abajo si la tienes en este dispositivo.",
    openInAuthenticator: "Abrir en la aplicación de autenticación",
    enterSecretManually: "O introduce la clave manualmente",
    enabledTitle: "Autenticación en dos pasos activada",
    enabledDescription:
      "Tu método de verificación está confirmado y 2FA ya está activo.",
    backupCodes: "Códigos de respaldo",
    backupCodesDescription:
      "Guarda estos códigos en un lugar seguro. Cada código se puede usar una vez si pierdes el acceso a tu método de verificación.",
    regenerateCodes: "Regenerar códigos de respaldo",
    errors: {
      fetch: "No se pudo obtener el estado de 2FA.",
      enable: "No se pudo activar 2FA.",
      disable: "No se pudo desactivar 2FA.",
      regenerate: "No se pudieron regenerar los códigos de respaldo.",
      verify: "La verificación falló. Inténtalo de nuevo.",
    },
  },
  stepUp: {
    title: "Confirma que eres tú",
    description:
      "Vuelve a autenticarte antes de guardar este cambio en la cuenta.",
    withPassword: "Usar contraseña",
    withProvider: "Usar {provider}",
    confirming: "Confirmando...",
    failed: "La reautenticación falló.",
    noMethods:
      "No hay métodos de reautenticación disponibles para esta cuenta.",
    chooseMethod: "Verificar con",
    methodPassword: "Contraseña",
    totpPrompt: "Introduce el código de 6 dígitos de tu app de autenticación.",
    sendPrompt: "Enviaremos un código de un solo uso a tu {method}.",
    codeSentTo: "Introduce el código que enviamos a {destination}.",
    backupPrompt: "Introduce uno de tus códigos de respaldo sin usar.",
    useBackup: "Usar un código de respaldo",
    useCode: "Usar un código de verificación",
    providerPrompt: "Te llevaremos a {provider} y te traeremos de vuelta aquí.",
    submit: "Confirmar",
  },
  account: {
    security: {
      title: "Acceso y seguridad",
      description: "Formas de iniciar sesión en tu cuenta",
    },
    contact: {
      title: "Datos de contacto",
      description:
        "Se usan para iniciar sesión, recuperar tu cuenta y recibir alertas de seguridad.",
      change: "Cambiar",
      add: "Añadir",
      verify: "Verificar",
      codeSentTo: "Introduce el código que enviamos a {value}.",
      codeBurned:
        "Ese código ya no se puede usar. Envía un código nuevo para continuar.",
      sendNewCode: "Enviar un código nuevo",
      phoneHint: "Incluye el prefijo del país, p. ej. +34 612 345 678.",
      noneSet: "No establecido",
      pending: "Verificación pendiente para {value}.",
      resendVerification: "Reenviar verificación",
      verificationSent: "Verificación enviada.",
      verificationFailed: "No se pudo enviar la verificación.",
    },
    email: {
      title: "Correo electrónico",
      add: "Añadir dirección de correo electrónico",
      changeTitle: "Actualizar dirección de correo",
      verifyTitle: "Verificar nuevo correo",
      changeDescription:
        "Introduce tu nuevo correo electrónico. Te enviaremos un código para confirmarlo.",
      codeSentDescription:
        "Enviamos un código de 6 dígitos a {email}. Ingrésalo abajo para completar el cambio.",
      newEmail: "Nueva dirección de correo",
      newEmailPlaceholder: "Ingresa nuevo correo electrónico",
      changeWarning:
        "Se enviará un código de verificación a tu nueva dirección de correo. Asegúrate de tener acceso antes de continuar.",
      codeExpiresInfo:
        "El código de verificación expirará en 15 minutos. Si no lo recibes, revisa tu carpeta de spam.",
      confirmChange: "Confirmar cambio",
      codeSent:
        "Se ha enviado un código de verificación a tu nueva dirección de correo.",
      codeResent: "Se ha enviado un nuevo código de verificación a tu correo.",
      changed: "¡Tu correo ha sido actualizado exitosamente!",
      unchanged: "El nuevo correo es igual al correo actual.",
      noPendingChange: "No hay solicitud de cambio de correo pendiente.",
    },
    phone: {
      title: "Número de teléfono",
      none: "Sin número de teléfono",
      add: "Agregar número de teléfono",
      change: "Cambiar teléfono",
      verify: "Verificar teléfono",
      changeTitle: "Actualizar número de teléfono",
      verifyTitle: "Verificar número de teléfono",
      changeDescription:
        "Introduce tu nuevo número de teléfono. Te enviaremos un código por SMS para confirmarlo.",
      changeWarning:
        "Se enviará un código de verificación a tu nuevo número de teléfono por SMS.",
      codeSent: "Se ha enviado un código de verificación a tu teléfono.",
      verified: "¡Número de teléfono verificado!",
      unchanged: "El nuevo número de teléfono es igual al actual.",
      noPendingChange:
        "No se encontró ningún cambio pendiente para este número. Empieza de nuevo.",
      smsUnavailable:
        "El envío de SMS no está disponible en este momento, por lo que cambiar tu número de teléfono está deshabilitado temporalmente.",
    },
    password: {
      title: "Contraseña",
      isSet: "Establecida",
      notSet: "Sin establecer",
      setHint:
        "Añade una contraseña para iniciar sesión también con tu correo o teléfono.",
      changeTitle: "Cambiar contraseña",
      setTitle: "Establecer contraseña",
      changeDescription:
        "Cambia la contraseña de tu cuenta. La nueva contraseña debe ser distinta de la actual.",
      setDescription:
        "Establece una contraseña para poder iniciar sesión también con tu correo y contraseña.",
      submit: "Actualizar contraseña",
      changed: "¡Contraseña actualizada exitosamente!",
      set: "¡Contraseña establecida exitosamente!",
      currentIncorrect: "La contraseña actual es incorrecta",
    },
    providers: {
      title: "Opciones de inicio de sesión vinculadas",
      description:
        "Vincula una cuenta social para iniciar sesión más rápido y recuperar el acceso.",
      linkWith: "Vincular con {provider}",
      linked: "Vinculada",
      notLinked: "No vinculada",
      link: "Vincular",
      linking: "Vinculando...",
      unlink: "Desvincular",
      unlinking: "Desvinculando...",
      unlinked: "Cuenta desvinculada correctamente",
      unlinkConfirmTitle: "¿Desvincular {provider}?",
      unlinkConfirmDescription:
        "No podrás iniciar sesión con {provider} hasta que lo vuelvas a vincular.",
      lastMethodHint:
        "Añade una contraseña o vincula otra opción de inicio de sesión antes de desvincular esta.",
    },
    wallet: {
      title: "Billetera Solana",
      notLinked: "Ninguna billetera vinculada",
      connected: "Conectada: {address}",
      linked: "Vinculada: {address}",
      verificationRequired:
        "Importada: {address}. Verifica la propiedad para usar esta billetera.",
      select: "Seleccionar billetera",
      link: "Vincular billetera",
      linking: "Vinculando...",
      verify: "Verificar billetera",
      verifying: "Verificando...",
      unlink: "Desvincular billetera",
      unlinking: "Desvinculando...",
      unlinkConfirm:
        "¿Seguro que quieres desvincular esta billetera de tu cuenta?",
      linkedSuccess: "Billetera vinculada correctamente",
      verifiedSuccess: "Billetera verificada correctamente",
      unlinkedSuccess: "Billetera desvinculada correctamente",
      notConnected: "Primero conecta una billetera.",
      unsupported: "Esta billetera no puede firmar mensajes.",
    },
    twoFactor: {
      title: "Autenticación en dos pasos",
      description:
        "Pide un segundo paso al iniciar sesión para que una contraseña robada no sea suficiente.",
      on: "Activada",
      off: "Desactivada",
      default: "Predeterminado",
      makeDefault: "Hacer predeterminado",
      remove: "Quitar",
      removeTitle: "¿Quitar {method}?",
      removeDescription:
        "Ya no podrás verificar inicios de sesión con este método.",
      add: "Añadir un método",
      enable: "Activar",
      chooseMethod: "Elige un método de verificación",
      confirmTotp:
        "Introduce el código de 6 dígitos que muestra la app para terminar.",
      codeSentTo: "Introduce el código que enviamos a {destination}.",
      yourEmail: "tu correo electrónico",
      activate: "Activar",
      disable: "Desactivar",
      disableTitle: "¿Desactivar la autenticación en dos pasos?",
      disableDescription:
        "Se quitarán todos los métodos de verificación y códigos de respaldo. Solo tu contraseña protegerá tu cuenta.",
      removedRoles:
        "Se quitaron los roles que requieren autenticación en dos pasos: {roles}.",
      backupTitle: "Códigos de respaldo",
      backupRemaining: "Quedan {count} códigos sin usar",
      regenerate: "Generar códigos nuevos",
      regenerateTitle: "¿Generar nuevos códigos de respaldo?",
      regenerateDescription:
        "Tus códigos de respaldo actuales dejarán de funcionar de inmediato.",
    },
    sessions: {
      title: "Sesiones activas",
      description: "Dispositivos con sesión iniciada en tu cuenta.",
      current: "Este dispositivo",
      lastActive: "Última actividad {time}",
      revoke: "Cerrar sesión",
      revokeAll: "Cerrar todas las demás sesiones",
      revoked: "Sesión cerrada",
      revokeSelected: "Cerrar las seleccionadas ({count})",
      revokeEverywhere: "Cerrar sesión en todas partes",
      revokeEverywhereTitle: "¿Cerrar sesión en todas partes?",
      revokeEverywhereDescription:
        "Se cerrará la sesión en todos los dispositivos, incluido este.",
      selectSession: "Seleccionar {device}",
      unknownDevice: "Dispositivo desconocido",
      device: "{browser} en {os}",
      signedIn: "Sesión iniciada {time}",
      noOthers: "No has iniciado sesión en ningún otro lugar.",
    },
    delete: {
      title: "Eliminar cuenta",
      dangerZone: "Zona de peligro",
      description: "Eliminar tu cuenta es irreversible. Piénsalo bien.",
      warningAccess:
        "Si eliminas tu cuenta, perderás el acceso a ella y a cualquier suscripción que hayas comprado.",
      warningPermanent:
        "Ten en cuenta que no podrás recuperar tu cuenta una vez eliminada.",
      confirmHint: "Para confirmar, escribe {word} en el campo de abajo.",
      confirmLabel: "Confirmación",
      confirmWord: "ELIMINAR",
      confirmMismatch:
        "Escribe {word} exactamente como se muestra para confirmar.",
      submit: "Eliminar cuenta",
      deleting: "Eliminando...",
      success: "Tu cuenta ha sido eliminada.",
      failed:
        "No pudimos eliminar tu cuenta. Inténtalo de nuevo o contacta con soporte.",
    },
  },
  username: {
    chooseTitle: "Elige tu nombre de usuario",
    chooseDescription:
      "Esta será tu identidad pública. Puedes cambiarlo más tarde en la configuración de tu perfil.",
    generatedDescription:
      "Tu nombre de usuario generado se muestra abajo. Puedes conservarlo o elegir uno nuevo.",
    placeholder: "Ingresa un nombre de usuario",
    checking: "Comprobando disponibilidad…",
    available: "Disponible",
    taken: "Ya está en uso",
    generate: "Generar nuevo nombre de usuario",
    suggestions: "Sugerencias",
    save: "Guardar nombre de usuario",
    updated: "Nombre de usuario actualizado",
    updatedDescription:
      "Tu nombre de usuario ha sido actualizado exitosamente.",
    updateFailed: "No se pudo actualizar el nombre de usuario",
    cooldown: "Podrás cambiar tu nombre de usuario de nuevo {when}.",
  },
  challenge: {
    codeSentTo: "Enviamos un código a {destination}.",
    codeResent: "Hay un código nuevo en camino.",
    codeBurned:
      "Ese código caducó o no se puede volver a usar. Envía un código nuevo para continuar.",
    sendNewCode: "Enviar un código nuevo",
    useFactor: "Usar {method} en su lugar",
  },
  enrollment: {
    title: "Configura la autenticación en dos pasos",
    chooseMethod: "Elige cómo recibirás los códigos de inicio de sesión.",
    startTotp: "Configurar autenticador",
    totpPrompt:
      "Luego introduce el código de 6 dígitos de la app para terminar.",
    codeSentPrompt:
      "Introduce el código que enviamos para terminar la configuración.",
    noMethod:
      "No hay ningún método de dos pasos disponible para esta cuenta. Contacta con soporte.",
    secretLabel: "Clave de configuración",
  },
  backupCodes: {
    title: "Guarda tus códigos de respaldo",
    signedIn:
      "Has iniciado sesión. Guarda estos códigos en un lugar seguro: cada uno funciona una vez si pierdes el acceso a tu método de verificación.",
    acknowledge: "He guardado mis códigos de respaldo",
    fileHeader: "Códigos de respaldo. Cada código se puede usar una vez.",
  },
  recovery: {
    title: "¿Restaurar tu cuenta?",
    description:
      "Esta cuenta fue eliminada. Puedes restaurarla hasta el {date}; después se eliminará definitivamente.",
    confirm: "Restaurar cuenta",
  },
  callback: {
    completing: "Completando el inicio de sesión…",
    errorTitle: "Error al iniciar sesión",
  },
  solana: {
    provider: "Solana",
    errors: {
      not_connected: "Conecta una billetera para continuar.",
      unsupported: "Esta billetera no puede firmar mensajes.",
      rejected: "Se rechazó la solicitud de firma.",
      invalid_signature: "La billetera devolvió una firma no válida.",
      busy: "La billetera está ocupada. Inténtalo de nuevo.",
    },
  },
  errors: {
    network_error: "Error de red. Comprueba tu conexión.",
    popup_blocked:
      "Se bloqueó la ventana de inicio de sesión. Permite las ventanas emergentes e inténtalo de nuevo.",
    popup_closed: "Se cerró la ventana de inicio de sesión.",
    popup_timeout: "La ventana de inicio de sesión caducó. Inténtalo de nuevo.",
    session_changed: "Tu sesión cambió en otra pestaña. Inténtalo de nuevo.",
    generic: "Algo salió mal. Inténtalo de nuevo.",
    network: "Error de red. Por favor verifica tu conexión.",
    "2fa_code_expired":
      "Ese código caducó o no se puede volver a usar. Envía un código nuevo.",
    "2fa_enrollment_required":
      "Debes configurar la autenticación de dos factores para terminar de iniciar sesión.",
    "2fa_factor_exists":
      "Ya hay un método de dos factores configurado. Elimínalo antes de agregar otro.",
    "2fa_method_unavailable": "Ese método de dos factores no está disponible.",
    "2fa_required": "Se requiere autenticación de dos factores.",
    access_denied: "Se canceló el inicio de sesión.",
    account_disabled: "Esta cuenta está deshabilitada.",
    account_exists_link_required:
      "Ya existe una cuenta con este correo. Inicia sesión y vincula el proveedor desde la página de tu cuenta.",
    account_recovery_expired:
      "El periodo de recuperación de la cuenta ha terminado.",
    account_recovery_required:
      "Confirma la recuperación de la cuenta antes de iniciar sesión.",
    auth_required_for_link: "Inicia sesión antes de vincular un proveedor.",
    authentication_failed: "La autenticación falló.",
    authentication_required: "Inicia sesión para continuar.",
    cannot_unlink_last_login_method:
      "No puedes desvincular tu último método de inicio de sesión.",
    challenge_expired: "Tu sesión de verificación expiró. Empieza de nuevo.",
    email_already_verified: "Tu correo electrónico ya está verificado.",
    email_delivery_failed:
      "No pudimos enviar el correo de verificación. Inténtalo de nuevo o contacta con soporte.",
    email_in_use: "Este correo electrónico ya está en uso.",
    email_password_reset_unavailable:
      "El restablecimiento de contraseña por correo no está disponible en este momento.",
    email_registration_unavailable:
      "El registro por correo no está disponible en este momento.",
    email_sender_unavailable:
      "El envío de correo no está disponible actualmente. Inténtalo más tarde.",
    email_unavailable: "El correo no está disponible en este momento.",
    email_unchanged: "El nuevo correo es igual al correo actual.",
    email_verification_failed: "No pudimos enviar el correo de verificación.",
    email_verification_unavailable:
      "La verificación por correo no está disponible en este momento.",
    enable_2fa_failed: "No se pudo activar la autenticación de dos factores.",
    failed_to_request_phone_change:
      "No se pudo solicitar el cambio de teléfono. Inténtalo más tarde.",
    failed_to_unlink: "No se pudo desvincular la cuenta.",
    forbidden: "No tienes permiso para hacer eso.",
    internal_error: "Algo salió mal de nuestro lado. Inténtalo de nuevo.",
    invalid_challenge: "Tu sesión 2FA es inválida o ha expirado.",
    invalid_code: "Código de verificación inválido.",
    invalid_credentials: "Correo o contraseña incorrectos.",
    invalid_email: "Ingresa un correo electrónico válido.",
    invalid_identifier:
      "Ingresa un correo electrónico o número de teléfono válido.",
    invalid_or_expired_code:
      "El código de verificación es inválido o ha expirado.",
    invalid_or_expired_token: "Este enlace no es válido o ha expirado.",
    invalid_password: "Contraseña incorrecta. Inténtalo de nuevo.",
    invalid_phone_number: "Ingresa un número de teléfono válido.",
    invalid_provider: "Ese proveedor de inicio de sesión no es compatible.",
    invalid_request:
      "Solicitud inválida. Revisa los datos e inténtalo de nuevo.",
    invalid_state: "La sesión de inicio no es válida. Inténtalo de nuevo.",
    missing_fields: "Completa todos los campos obligatorios.",
    not_authenticated: "Inicia sesión para continuar.",
    oidc_begin_failed:
      "No se pudo iniciar el inicio de sesión con el proveedor.",
    oidc_exchange_failed:
      "No se pudo completar el inicio de sesión con el proveedor.",
    owner_slug_taken: "Este nombre de usuario ya está en uso.",
    passkey_failed: "La operación con la llave de acceso falló.",
    passkey_not_found: "No se encontró la llave de acceso.",
    password_change_failed: "No se pudo cambiar la contraseña.",
    password_contains_identifier:
      "La contraseña no puede contener tu nombre de usuario ni tu correo.",
    password_requirements_unmet: "La contraseña no cumple los requisitos.",
    password_reset_required:
      "Tu cuenta es anterior a nuestro nuevo sistema de inicio de sesión. Restablece tu contraseña para continuar.",
    password_too_common:
      "Esta contraseña es demasiado común. Elige una menos predecible.",
    password_too_long: "La contraseña es demasiado larga.",
    password_too_short: "La contraseña debe tener al menos 8 caracteres.",
    passwordless_disabled:
      "El inicio de sesión sin contraseña está deshabilitado.",
    pending_registration_not_found:
      "No se encontró un registro pendiente para esa dirección o número. Regístrate de nuevo.",
    phone_2fa_unavailable:
      "La autenticación de dos factores por SMS no está disponible.",
    phone_already_verified: "Tu número de teléfono ya está verificado.",
    phone_and_code_required: "Se requiere un número de teléfono.",
    phone_in_use: "Este número de teléfono ya está en uso.",
    phone_number_must_be_e164:
      "Ingresa el número en formato internacional, p. ej. +1234567890.",
    phone_registration_unavailable:
      "El registro por teléfono no está disponible en este momento; regístrate con un correo electrónico en su lugar.",
    phone_unavailable:
      "La verificación por teléfono no está disponible actualmente. Usa el correo electrónico en su lugar.",
    phone_unchanged: "El nuevo número de teléfono es igual al actual.",
    phone_verification_failed: "No pudimos enviar el mensaje de verificación.",
    phone_verification_unavailable:
      "La verificación por teléfono no está disponible en este momento.",
    provider_already_linked:
      "Esta cuenta del proveedor ya está vinculada a otro usuario.",
    provider_change_requires_unlink:
      "Desvincula la cuenta actual antes de vincular otra.",
    provider_error: "El proveedor devolvió un error. Inténtalo de nuevo.",
    provider_link_failed: "No se pudo vincular la cuenta.",
    provider_not_linked: "Ese proveedor no está vinculado.",
    rate_limited: "Demasiados intentos. Inténtalo de nuevo más tarde.",
    regenerate_codes_failed:
      "No se pudieron regenerar los códigos de respaldo.",
    registration_disabled: "El registro está deshabilitado en este momento.",
    rename_rate_limited:
      "Demasiados cambios de nombre de usuario. Inténtalo más tarde.",
    renames_disabled: "Los cambios de nombre de usuario están deshabilitados.",
    send_code_failed: "No se pudo enviar el código. Inténtalo de nuevo.",
    session_creation_failed: "No se pudo crear la sesión.",
    siws_challenge_expired:
      "La solicitud de inicio con la billetera expiró. Inténtalo de nuevo.",
    siws_signature_invalid: "La firma de la billetera no es válida.",
    sms_delivery_failed:
      "No pudimos enviar el mensaje de texto de verificación. Prueba con el correo electrónico o contacta con soporte.",
    sms_unavailable:
      "El SMS no está disponible actualmente. Usa el correo electrónico en su lugar.",
    step_up_failed: "La verificación falló. Inténtalo de nuevo.",
    step_up_required: "Confirma que eres tú para continuar.",
    token_expired: "Tu sesión expiró. Inicia sesión de nuevo.",
    token_revoked: "Tu sesión terminó. Inicia sesión de nuevo.",
    unauthorized: "Inicia sesión para continuar.",
    unknown_provider: "Proveedor de inicio de sesión desconocido.",
    user_banned: "Tu cuenta está deshabilitada.",
    user_not_found: "Usuario no encontrado.",
    username_cannot_contain_at: "El nombre de usuario no puede contener @.",
    username_cannot_start_with_plus:
      "El nombre de usuario no puede comenzar con +.",
    username_in_use: "Este nombre de usuario ya está en uso.",
    username_invalid_characters:
      "El nombre de usuario solo puede contener letras, números y guiones bajos (_).",
    username_must_start_with_letter:
      "El nombre de usuario debe comenzar con una letra.",
    username_not_allowed: "Este nombre de usuario no está permitido.",
    username_too_long:
      "El nombre de usuario debe tener como máximo 30 caracteres.",
    username_too_short:
      "El nombre de usuario debe tener al menos 4 caracteres.",
    verification_link_expired: "Este enlace de verificación ha expirado.",
    verification_required: "Verifica tus datos de contacto para continuar.",
    wallet_already_linked: "Esa billetera ya está vinculada a otra cuenta.",
    wallet_change_requires_unlink:
      "Desvincula tu billetera actual antes de conectar otra.",
  },
}
