import type { AuthUiMessageBundle } from "../i18n/messages.ts"

export const de: AuthUiMessageBundle = {
  common: {
    continue: "Weiter",
    cancel: "Abbrechen",
    back: "Zurück",
    close: "Schließen",
    confirm: "Bestätigen",
    save: "Speichern",
    saving: "Speichern...",
    verify: "Verifizieren",
    verifying: "Wird verifiziert...",
    sending: "Wird gesendet...",
    loading: "Laden...",
    sendCode: "Code senden",
    resendCode: "Code erneut senden",
    resendIn: "Code erneut senden in {seconds}s",
    or: "oder",
    orContinueWith: "Oder weiter mit",
    showPassword: "Passwort anzeigen",
    hidePassword: "Passwort verbergen",
    copy: "Kopieren",
    copied: "Kopiert",
    download: "Als .txt herunterladen",
    tryAgain: "Erneut versuchen",
    goHome: "Zur Startseite",
    verified: "Verifiziert",
    unverified: "Nicht verifiziert",
    enabled: "Aktiviert",
    disabled: "Deaktiviert",
  },
  fields: {
    identifier: "E-Mail / Telefon / Benutzername",
    emailOrPhone: "E-Mail oder Telefon",
    email: "E-Mail",
    emailPlaceholder: "sie@beispiel.de",
    phone: "Telefonnummer",
    phonePlaceholder: "Telefonnummer eingeben",
    username: "Benutzername",
    usernameOptional: "Benutzername (optional)",
    password: "Passwort",
    confirmPassword: "Passwort bestätigen",
    currentPassword: "Aktuelles Passwort",
    currentPasswordPlaceholder: "Aktuelles Passwort eingeben",
    newPassword: "Neues Passwort",
    verificationCode: "Verifizierungscode",
    codePlaceholder: "Code eingeben",
    generatePassword: "Sicheres zufälliges Passwort generieren",
  },
  validation: {
    identifierRequired:
      "Geben Sie Ihre E-Mail, Telefonnummer oder Ihren Benutzernamen ein",
    emailOrPhoneRequired:
      "Geben Sie Ihre E-Mail-Adresse oder Telefonnummer ein",
    emailInvalid: "Gültige E-Mail eingeben",
    phoneInvalid: "Geben Sie eine gültige Telefonnummer ein, z. B. +1234567890",
    usernameRequired: "Benutzername erforderlich",
    usernameTooShort: "Benutzername muss mindestens {min} Zeichen lang sein.",
    usernameTooLong: "Benutzername darf {max} Zeichen nicht überschreiten.",
    usernameStartWithLetter:
      "Der Benutzername muss mit einem Buchstaben beginnen.",
    usernameCharacters:
      "Der Benutzername darf nur Buchstaben, Zahlen und Unterstriche (_) enthalten.",
    passwordRequired: "Geben Sie Ihr Passwort ein",
    passwordMinLength: "Das Passwort muss mindestens {min} Zeichen lang sein",
    passwordNeedsVariety:
      "Das Passwort muss einen Großbuchstaben, einen Kleinbuchstaben und eine Zahl enthalten",
    confirmPasswordRequired: "Bitte bestätigen Sie Ihr Passwort",
    passwordsDoNotMatch: "Passwörter stimmen nicht überein",
    newPasswordMustDiffer:
      "Das neue Passwort muss sich vom aktuellen Passwort unterscheiden",
    codeRequired: "Bitte geben Sie den Bestätigungscode ein.",
    codeLength: "Geben Sie den vollständigen {length}-stelligen Code ein",
  },
  signIn: {
    title: "Anmelden",
    titleCombined: "Anmelden / Registrieren",
    description:
      "Melden Sie sich an oder erstellen Sie ein Konto, um fortzufahren",
    submit: "Anmelden",
    forgotPassword: "Passwort vergessen?",
    noAccount: "Noch kein Konto?",
    createAccount: "Konto erstellen",
    continueWith: "Weiter mit {provider}",
    connecting: "Verbinde...",
    success: "Erfolgreich angemeldet",
    signedOut: "Erfolgreich abgemeldet",
    sessionExpiredTitle: "Sitzung abgelaufen",
    sessionExpiredDescription:
      "Sie wurden abgemeldet. Bitte melden Sie sich erneut an.",
    accountUnavailable:
      "Dieses Konto kann nicht zur Anmeldung verwendet werden. Es wurde möglicherweise geschlossen oder eingeschränkt. Wenn Sie denken, dass dies ein Fehler ist, kontaktieren Sie bitte den Support.",
  },
  register: {
    title: "Konto erstellen",
    submit: "Registrieren",
    haveAccount: "Bereits ein Konto?",
    signIn: "Anmelden",
    signUpWith: "Registrieren mit {provider}",
    legalPrefix: "Mit der Registrierung akzeptieren Sie unsere",
    terms: "Nutzungsbedingungen",
    privacy: "Datenschutzrichtlinie",
    and: "und",
    success: "Registrierung erfolgreich! Bitte überprüfen Sie Ihre E-Mail.",
    phoneUnavailable:
      "Die Anmeldung per Telefon ist derzeit nicht verfügbar — bitte registrieren Sie sich stattdessen mit einer E-Mail-Adresse.",
  },
  verify: {
    title: "Verifizieren Sie Ihr Konto",
    titleEmail: "Bestätigen Sie Ihre E-Mail",
    titlePhone: "Bestätigen Sie Ihre Telefonnummer",
    pleaseVerify: "Bitte verifizieren Sie Ihr Konto, um fortzufahren.",
    codeSentTo: "Wir haben einen Bestätigungscode an {destination} gesendet.",
    instructions:
      "Bitte geben Sie den Code unten ein, um Ihre Registrierung abzuschließen.",
    submitEmail: "E-Mail verifizieren",
    submitPhone: "Telefon verifizieren",
    didntReceive: "Code nicht erhalten?",
    resend: "Erneut senden",
    codeSent:
      "Verifizierungscode gesendet! Bitte überprüfen Sie Ihre Nachrichten.",
    verifying: "Wird verifiziert...",
    success: "Verifiziert!",
    successDescription:
      "Erfolgreich verifiziert! Sie können sich jetzt anmelden.",
    successSignedIn: "Verifiziert und erfolgreich angemeldet!",
    errorTitle: "Verifizierungsfehler",
    emailAlreadyVerifiedTitle: "Ihre E-Mail-Adresse ist bereits bestätigt",
    emailAlreadyVerifiedDescription:
      "Die E-Mail-Adresse Ihres Kontos ist bereits bestätigt. Sie können Ihr Konto weiter verwenden.",
    phoneAlreadyVerifiedTitle: "Ihre Telefonnummer ist bereits bestätigt",
    phoneAlreadyVerifiedDescription:
      "Die Telefonnummer Ihres Kontos ist bereits bestätigt. Sie können Ihr Konto weiter verwenden.",
    linkExpiredTitle: "Ihr Bestätigungslink ist abgelaufen",
    emailLinkExpiredDescription:
      "E-Mail-Bestätigungslinks laufen nach 60 Minuten ab. Sende eine weitere Bestätigungs-E-Mail, um fortzufahren.",
    phoneLinkExpiredDescription:
      "Bestätigungslinks per Textnachricht laufen nach 15 Minuten ab. Sende eine weitere Bestätigungsnachricht, um fortzufahren.",
    invalidLinkTitle: "Ungültiger Bestätigungslink",
    invalidLinkDescription:
      "Dieser Bestätigungslink ist ungültig. Fordere bitte einen neuen an.",
    sendAgain: "Erneut senden",
    cancelRegistration: "Registrierung abbrechen",
    keepRegistration: "Registrierung behalten",
    cancelConfirmTitle: "Registrierung abbrechen?",
    cancelConfirmDescription:
      "Dies löscht Ihre ausstehende Registrierung für {identifier} endgültig. Geben Sie zur Bestätigung Ihr Passwort ein.",
    cancelFailed: "Registrierung konnte nicht abgebrochen werden.",
  },
  resetPassword: {
    requestTitle: "Passwort zurücksetzen",
    requestDescription:
      "Geben Sie Ihre E-Mail oder Telefonnummer ein, und wir senden Ihnen einen Link zum Zurücksetzen.",
    sendLink: "Link senden",
    emailSentTitle: "Überprüfen Sie Ihre E-Mail",
    emailSentDescription:
      "Wir haben Anweisungen zum Zurücksetzen des Passworts an Ihre E-Mail gesendet. Folgen Sie dem Link, um ein neues Passwort festzulegen.",
    smsSentTitle: "Überprüfen Sie Ihre Nachrichten",
    smsSentDescription:
      "Wir haben Ihnen per SMS Anweisungen zum Zurücksetzen des Passworts an Ihr Telefon gesendet. Folgen Sie dem Link, um ein neues Passwort festzulegen.",
    title: "Passwort zurücksetzen",
    instructions:
      "Geben Sie den an Ihre E-Mail oder Ihr Telefon gesendeten Bestätigungscode ein und wählen Sie dann ein neues Passwort.",
    submit: "Passwort zurücksetzen",
    successTitle: "Passwort erfolgreich zurückgesetzt",
    successDescription:
      "Ihr Passwort wurde aktualisiert. Sie können sich jetzt damit anmelden.",
    errorTitle: "Fehler beim Zurücksetzen des Passworts",
    invalidLink:
      "Dieser Link zum Zurücksetzen des Passworts ist ungültig oder abgelaufen. Fordere bitte einen neuen an.",
    required:
      "Ihr Konto stammt aus der Zeit vor unserem neuen Anmeldesystem. Bitte setzen Sie Ihr Passwort zurück, um fortzufahren.",
  },
  twoFactor: {
    title: "Zwei-Faktor-Authentifizierung",
    challengeTitle: "Bestätigen Sie Ihre Identität",
    codePrompt: "Geben Sie den an Ihre(n) {method} gesendeten 2FA-Code ein.",
    codePromptTotp:
      "Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein.",
    backupPrompt: "Geben Sie einen Ihrer Backup-Codes ein, um fortzufahren.",
    backupPlaceholder: "Backup-Code eingeben",
    useBackup: "Backup-Code verwenden",
    useCode: "Bestätigungscode verwenden",
    codeExpires: "Codes laufen in {minutes} Minuten ab.",
    enrollmentRequired:
      "Die Einrichtung der Zwei-Faktor-Authentifizierung ist erforderlich, um die Anmeldung abzuschließen.",
    methods: {
      email: "E-Mail",
      sms: "SMS",
      totp: "Authenticator-App",
    },
    hints: {
      email: "Wir senden Ihnen einen Code per E-Mail.",
      sms: "Wir senden Ihnen einen Code per SMS.",
      totp: "Erzeuge Codes in einer App wie Google Authenticator.",
      smsUnavailable: "SMS-Zustellung ist derzeit nicht verfügbar.",
    },
    manageTitle: "Zwei-Faktor-Authentifizierung verwalten",
    manageDescription:
      "Aktiviere oder deaktiviere die Zwei-Faktor-Authentifizierung oder erstelle neue Backup-Codes.",
    manage: "Verwalten",
    status: "Status",
    selectMethod: "Bestätigungsmethode",
    enable: "2FA aktivieren",
    disable: "2FA deaktivieren",
    scanQr:
      "Scannen Sie dies mit Ihrer Authenticator-App oder tippen Sie unten, wenn sie auf diesem Gerät ist.",
    openInAuthenticator: "In Authenticator-App öffnen",
    enterSecretManually: "Oder den Schlüssel manuell eingeben",
    enabledTitle: "Zwei-Faktor-Authentifizierung aktiviert",
    enabledDescription:
      "Ihre Bestätigungsmethode wurde verifiziert und 2FA ist jetzt aktiv.",
    backupCodes: "Backup-Codes",
    backupCodesDescription:
      "Bewahren Sie diese Codes an einem sicheren Ort auf. Jeder Code kann einmal verwendet werden, falls Sie keinen Zugriff mehr auf Ihre Bestätigungsmethode haben.",
    regenerateCodes: "Backup-Codes neu generieren",
    errors: {
      fetch: "2FA-Status konnte nicht abgerufen werden.",
      enable: "2FA konnte nicht aktiviert werden.",
      disable: "2FA konnte nicht deaktiviert werden.",
      regenerate: "Backup-Codes konnten nicht neu generiert werden.",
      verify: "Verifizierung fehlgeschlagen. Bitte versuche es erneut.",
    },
  },
  stepUp: {
    title: "Bestätigen Sie Ihre Identität",
    description:
      "Authentifizieren Sie sich erneut, bevor Sie diese Kontoänderung speichern.",
    withPassword: "Passwort verwenden",
    withProvider: "{provider} verwenden",
    confirming: "Wird bestätigt...",
    failed: "Erneute Authentifizierung fehlgeschlagen.",
    noMethods:
      "Für dieses Konto sind keine Methoden zur erneuten Authentifizierung verfügbar.",
  },
  account: {
    security: {
      title: "Anmeldung & Sicherheit",
      description: "Möglichkeiten, sich bei Ihrem Konto anzumelden",
    },
    contact: {
      noneSet: "Nicht festgelegt",
      pending: "Verifizierung ausstehend für {value}.",
      resendVerification: "Verifizierung erneut senden",
      verificationSent: "Bestätigung gesendet.",
      verificationFailed: "Bestätigung konnte nicht gesendet werden.",
    },
    email: {
      title: "E-Mail",
      add: "E-Mail-Adresse hinzufügen",
      changeTitle: "E-Mail-Adresse aktualisieren",
      verifyTitle: "Neue E-Mail verifizieren",
      changeDescription:
        "Geben Sie Ihre neue E-Mail-Adresse und Ihr aktuelles Passwort ein, um fortzufahren.",
      codeSentDescription:
        "Wir haben einen 6-stelligen Code an {email} gesendet. Geben Sie ihn unten ein, um die Änderung abzuschließen.",
      newEmail: "Neue E-Mail-Adresse",
      newEmailPlaceholder: "Neue E-Mail-Adresse eingeben",
      changeWarning:
        "Ein Bestätigungscode wird an Ihre neue E-Mail-Adresse gesendet. Stellen Sie sicher, dass Sie darauf zugreifen können, bevor Sie fortfahren.",
      codeExpiresInfo:
        "Der Bestätigungscode läuft in 15 Minuten ab. Wenn Sie ihn nicht erhalten, überprüfen Sie Ihren Spam-Ordner.",
      confirmChange: "Änderung bestätigen",
      codeSent:
        "Ein Bestätigungscode wurde an Ihre neue E-Mail-Adresse gesendet.",
      codeResent: "Ein neuer Bestätigungscode wurde an Ihre E-Mail gesendet.",
      changed: "Ihre E-Mail wurde erfolgreich aktualisiert!",
      unchanged: "Die neue E-Mail ist dieselbe wie die aktuelle E-Mail.",
      noPendingChange: "Keine ausstehende E-Mail-Änderungsanfrage.",
    },
    phone: {
      title: "Telefonnummer",
      none: "Keine Telefonnummer hinterlegt",
      add: "Telefonnummer hinzufügen",
      change: "Telefonnummer ändern",
      verify: "Telefon verifizieren",
      changeTitle: "Telefonnummer aktualisieren",
      verifyTitle: "Telefonnummer verifizieren",
      changeDescription:
        "Geben Sie Ihre neue Telefonnummer und Ihr aktuelles Passwort ein, um einen Verifizierungscode zu erhalten.",
      changeWarning:
        "Ein Verifizierungscode wird per SMS an Ihre neue Telefonnummer gesendet.",
      codeSent: "Ein Verifizierungscode wurde an Ihr Telefon gesendet.",
      verified: "Telefonnummer verifiziert!",
      unchanged: "Die neue Telefonnummer ist identisch mit Ihrer aktuellen.",
      noPendingChange:
        "Keine ausstehende Änderung für diese Nummer gefunden. Bitte beginnen Sie erneut.",
      smsUnavailable:
        "Der SMS-Versand ist derzeit nicht verfügbar, daher kann Ihre Telefonnummer vorübergehend nicht geändert werden.",
    },
    password: {
      changeTitle: "Passwort ändern",
      setTitle: "Passwort festlegen",
      changeDescription:
        "Ändern Sie Ihr Kontopasswort. Das neue Passwort muss sich von Ihrem aktuellen unterscheiden.",
      setDescription:
        "Legen Sie ein Passwort fest, damit Sie sich auch mit E-Mail und Passwort anmelden können.",
      submit: "Passwort aktualisieren",
      changed: "Passwort erfolgreich aktualisiert!",
      set: "Passwort erfolgreich festgelegt!",
      currentIncorrect: "Aktuelles Passwort ist falsch",
    },
    providers: {
      title: "Verknüpfte Login-Optionen",
      description:
        "Verknüpfen Sie ein Social-Konto für schnellere Anmeldung und Kontowiederherstellung.",
      linkWith: "Mit {provider} verknüpfen",
      linked: "Verknüpft",
      notLinked: "Nicht verknüpft",
      link: "Verknüpfen",
      linking: "Wird verknüpft...",
      unlink: "Verknüpfung lösen",
      unlinking: "Wird getrennt...",
      unlinked: "Konto erfolgreich getrennt",
    },
    wallet: {
      title: "Solana-Wallet",
      notLinked: "Keine Wallet verknüpft",
      connected: "Verbunden: {address}",
      linked: "Verknüpft: {address}",
      verificationRequired:
        "Importiert: {address}. Bestätige den Besitz, um diese Wallet zu verwenden.",
      select: "Wallet auswählen",
      link: "Wallet verknüpfen",
      linking: "Verknüpfen...",
      verify: "Wallet bestätigen",
      verifying: "Wird bestätigt...",
      unlink: "Wallet trennen",
      unlinking: "Trennen...",
      unlinkConfirm:
        "Möchten Sie diese Wallet wirklich von Ihrem Konto trennen?",
      linkedSuccess: "Wallet erfolgreich verknüpft",
      verifiedSuccess: "Wallet erfolgreich bestätigt",
      unlinkedSuccess: "Wallet erfolgreich getrennt",
    },
    sessions: {
      title: "Aktive Sitzungen",
      description: "Geräte, die derzeit bei Ihrem Konto angemeldet sind.",
      current: "Dieses Gerät",
      lastActive: "Zuletzt aktiv {time}",
      revoke: "Abmelden",
      revokeAll: "Von allen anderen Sitzungen abmelden",
      revoked: "Sitzung abgemeldet",
    },
    delete: {
      title: "Konto löschen",
      dangerZone: "Gefahrenzone",
      description:
        "Das Löschen Ihres Kontos ist unwiderruflich. Bitte überlegen Sie es sich gut.",
      warningAccess:
        "Wenn Sie Ihr Konto löschen, verlieren Sie den Zugriff darauf und auf alle gekauften Abonnements.",
      warningPermanent:
        "Bitte beachten Sie, dass Sie Ihr Konto nach dem Löschen nicht wiederherstellen können.",
      confirmHint: "Geben Sie zur Bestätigung {word} in das Feld unten ein.",
      confirmLabel: "Bestätigung",
      confirmWord: "LÖSCHEN",
      confirmMismatch:
        "Geben Sie {word} genau wie angezeigt ein, um zu bestätigen.",
      submit: "Konto löschen",
      deleting: "Wird gelöscht...",
      success: "Ihr Konto wurde gelöscht.",
      failed:
        "Wir konnten Ihr Konto nicht löschen. Bitte versuchen Sie es erneut oder kontaktieren Sie den Support.",
    },
  },
  username: {
    chooseTitle: "Wählen Sie Ihren Benutzernamen",
    chooseDescription:
      "Dies wird Ihre öffentliche Identität. Sie können ihn später in Ihren Profileinstellungen ändern.",
    generatedDescription:
      "Ihr generierter Benutzername wird unten angezeigt. Sie können ihn behalten oder einen neuen wählen.",
    placeholder: "Benutzername eingeben",
    checking: "Verfügbarkeit wird geprüft…",
    available: "Verfügbar",
    taken: "Bereits vergeben",
    generate: "Neuen Benutzernamen generieren",
    suggestions: "Vorschläge",
    save: "Benutzername speichern",
    updated: "Benutzername aktualisiert",
    updatedDescription: "Ihr Benutzername wurde erfolgreich aktualisiert.",
    updateFailed: "Benutzername konnte nicht aktualisiert werden",
    cooldown: "Sie können Ihren Benutzernamen {when} wieder ändern.",
  },
  errors: {
    generic: "Etwas ist schiefgelaufen. Bitte versuchen Sie es erneut.",
    network: "Netzwerkfehler. Bitte überprüfen Sie Ihre Verbindung.",
    "2fa_enrollment_required":
      "Die Einrichtung der Zwei-Faktor-Authentifizierung ist erforderlich, um die Anmeldung abzuschließen.",
    "2fa_factor_exists":
      "Es ist bereits eine Zwei-Faktor-Methode eingerichtet. Entfernen Sie sie, bevor Sie eine andere hinzufügen.",
    "2fa_method_unavailable": "Diese Zwei-Faktor-Methode ist nicht verfügbar.",
    "2fa_required": "Zwei-Faktor-Authentifizierung ist erforderlich.",
    access_denied: "Die Anmeldung wurde abgebrochen.",
    account_disabled: "Dieses Konto ist deaktiviert.",
    account_exists_link_required:
      "Ein Konto mit dieser E-Mail existiert bereits. Melden Sie sich an und verknüpfen Sie den Anbieter auf Ihrer Kontoseite.",
    account_recovery_expired:
      "Der Zeitraum für die Kontowiederherstellung ist abgelaufen.",
    account_recovery_required:
      "Bestätigen Sie die Kontowiederherstellung, bevor Sie sich anmelden.",
    auth_required_for_link:
      "Melden Sie sich an, bevor Sie einen Anbieter verknüpfen.",
    authentication_failed: "Authentifizierung fehlgeschlagen.",
    authentication_required: "Bitte melden Sie sich an, um fortzufahren.",
    cannot_unlink_last_login_method:
      "Sie können Ihre letzte Anmeldemöglichkeit nicht entfernen.",
    challenge_expired:
      "Ihre Bestätigungssitzung ist abgelaufen. Bitte beginnen Sie erneut.",
    email_already_verified: "Ihre E-Mail-Adresse ist bereits verifiziert.",
    email_delivery_failed:
      "Die Verifizierungs-E-Mail konnte nicht zugestellt werden. Bitte versuchen Sie es erneut oder wenden Sie sich an den Support.",
    email_in_use: "Diese E-Mail-Adresse wird bereits verwendet.",
    email_password_reset_unavailable:
      "Das Zurücksetzen des Passworts per E-Mail ist derzeit nicht verfügbar.",
    email_registration_unavailable:
      "Die Registrierung per E-Mail ist derzeit nicht verfügbar.",
    email_sender_unavailable:
      "Der E-Mail-Versand ist derzeit nicht verfügbar. Bitte versuche es später erneut.",
    email_unavailable: "E-Mail ist derzeit nicht verfügbar.",
    email_unchanged: "Die neue E-Mail ist dieselbe wie die aktuelle E-Mail.",
    email_verification_failed:
      "Die Bestätigungs-E-Mail konnte nicht gesendet werden.",
    email_verification_unavailable:
      "Die E-Mail-Bestätigung ist derzeit nicht verfügbar.",
    enable_2fa_failed:
      "Die Zwei-Faktor-Authentifizierung konnte nicht aktiviert werden.",
    failed_to_request_phone_change:
      "Telefonnummer konnte nicht geändert werden. Bitte versuchen Sie es später erneut.",
    failed_to_unlink: "Das Konto konnte nicht getrennt werden.",
    forbidden: "Dazu haben Sie keine Berechtigung.",
    internal_error:
      "Bei uns ist etwas schiefgelaufen. Bitte versuche es erneut.",
    invalid_challenge: "Ihre 2FA-Sitzung ist ungültig oder abgelaufen.",
    invalid_code: "Ungültiger Verifizierungscode.",
    invalid_credentials: "Falsche E-Mail oder falsches Passwort.",
    invalid_email: "Bitte geben Sie eine gültige E-Mail-Adresse ein.",
    invalid_identifier:
      "Bitte geben Sie eine gültige E-Mail-Adresse oder Telefonnummer ein.",
    invalid_or_expired_code:
      "Der Bestätigungscode ist ungültig oder abgelaufen.",
    invalid_or_expired_token: "Dieser Link ist ungültig oder abgelaufen.",
    invalid_password: "Falsches Passwort. Bitte versuchen Sie es erneut.",
    invalid_phone_number: "Bitte geben Sie eine gültige Telefonnummer ein.",
    invalid_provider: "Dieser Anmeldeanbieter wird nicht unterstützt.",
    invalid_request:
      "Ungültige Anfrage. Bitte prüfen Sie Ihre Eingaben und versuchen Sie es erneut.",
    invalid_state:
      "Die Anmeldesitzung ist ungültig. Bitte versuchen Sie es erneut.",
    missing_fields: "Bitte füllen Sie alle Pflichtfelder aus.",
    not_authenticated: "Bitte melden Sie sich an, um fortzufahren.",
    oidc_begin_failed:
      "Die Anmeldung beim Anbieter konnte nicht gestartet werden.",
    oidc_exchange_failed:
      "Die Anmeldung beim Anbieter konnte nicht abgeschlossen werden.",
    owner_slug_taken: "Dieser Benutzername ist bereits vergeben.",
    passkey_failed: "Der Passkey-Vorgang ist fehlgeschlagen.",
    passkey_not_found: "Der Passkey wurde nicht gefunden.",
    password_change_failed: "Das Passwort konnte nicht geändert werden.",
    password_reset_required:
      "Ihr Konto stammt aus der Zeit vor unserem neuen Anmeldesystem. Bitte setzen Sie Ihr Passwort zurück, um fortzufahren.",
    password_too_short: "Das Passwort muss mindestens 8 Zeichen lang sein.",
    passwordless_disabled: "Die passwortlose Anmeldung ist deaktiviert.",
    pending_registration_not_found:
      "Für diese Adresse oder Nummer wurde keine ausstehende Registrierung gefunden. Bitte registrieren Sie sich erneut.",
    phone_2fa_unavailable:
      "SMS-Zwei-Faktor-Authentifizierung ist nicht verfügbar.",
    phone_already_verified: "Ihre Telefonnummer ist bereits verifiziert.",
    phone_and_code_required: "Eine Telefonnummer ist erforderlich.",
    phone_in_use: "Diese Telefonnummer wird bereits verwendet.",
    phone_number_must_be_e164:
      "Geben Sie die Telefonnummer im internationalen Format ein, z. B. +1234567890.",
    phone_registration_unavailable:
      "Die Anmeldung per Telefon ist derzeit nicht verfügbar — bitte registrieren Sie sich stattdessen mit einer E-Mail-Adresse.",
    phone_unavailable:
      "Die Telefonverifizierung ist derzeit nicht verfügbar. Bitte verwende stattdessen E-Mail.",
    phone_unchanged:
      "Die neue Telefonnummer ist identisch mit Ihrer aktuellen.",
    phone_verification_failed:
      "Die Bestätigungs-SMS konnte nicht gesendet werden.",
    phone_verification_unavailable:
      "Die Telefonbestätigung ist derzeit nicht verfügbar.",
    provider_already_linked:
      "Dieses Anbieterkonto ist bereits mit einem anderen Benutzer verknüpft.",
    provider_change_requires_unlink:
      "Trennen Sie zuerst das aktuelle Konto, bevor Sie ein anderes verknüpfen.",
    provider_error:
      "Der Anbieter hat einen Fehler gemeldet. Bitte versuchen Sie es erneut.",
    provider_link_failed: "Das Konto konnte nicht verknüpft werden.",
    provider_not_linked: "Dieser Anbieter ist nicht verknüpft.",
    rate_limited: "Zu viele Versuche. Bitte versuchen Sie es später erneut.",
    regenerate_codes_failed:
      "Die Backup-Codes konnten nicht neu erstellt werden.",
    registration_disabled: "Die Registrierung ist derzeit deaktiviert.",
    rename_rate_limited:
      "Zu viele Änderungen des Benutzernamens. Bitte versuchen Sie es später erneut.",
    renames_disabled: "Änderungen des Benutzernamens sind deaktiviert.",
    send_code_failed:
      "Der Code konnte nicht gesendet werden. Bitte versuchen Sie es erneut.",
    session_creation_failed: "Die Sitzung konnte nicht erstellt werden.",
    siws_challenge_expired:
      "Die Wallet-Anmeldeanfrage ist abgelaufen. Bitte versuchen Sie es erneut.",
    siws_signature_invalid: "Die Wallet-Signatur ist ungültig.",
    sms_delivery_failed:
      "Die Verifizierungs-SMS konnte nicht zugestellt werden. Bitte versuchen Sie es stattdessen per E-Mail oder wenden Sie sich an den Support.",
    sms_unavailable:
      "SMS ist derzeit nicht verfügbar. Bitte verwende stattdessen E-Mail.",
    step_up_failed:
      "Die Bestätigung ist fehlgeschlagen. Bitte versuchen Sie es erneut.",
    step_up_required: "Bitte bestätigen Sie Ihre Identität, um fortzufahren.",
    token_expired:
      "Ihre Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.",
    token_revoked:
      "Ihre Sitzung wurde beendet. Bitte melden Sie sich erneut an.",
    unauthorized: "Bitte melden Sie sich an, um fortzufahren.",
    unknown_provider: "Unbekannter Anmeldeanbieter.",
    user_banned: "Ihr Konto ist deaktiviert.",
    user_not_found: "Benutzer nicht gefunden.",
    username_cannot_contain_at: "Der Benutzername darf kein @ enthalten.",
    username_cannot_start_with_plus:
      "Der Benutzername darf nicht mit + beginnen.",
    username_in_use: "Dieser Benutzername wird bereits verwendet.",
    username_invalid_characters:
      "Der Benutzername darf nur Buchstaben, Zahlen und Unterstriche (_) enthalten.",
    username_must_start_with_letter:
      "Der Benutzername muss mit einem Buchstaben beginnen.",
    username_not_allowed: "Dieser Benutzername ist nicht erlaubt.",
    username_too_long: "Der Benutzername darf höchstens 30 Zeichen lang sein.",
    username_too_short: "Der Benutzername muss mindestens 4 Zeichen lang sein.",
    verification_link_expired: "Dieser Verifizierungslink ist abgelaufen.",
    verification_required: "Bestätigen Sie Ihre Kontaktdaten, um fortzufahren.",
    wallet_already_linked:
      "Diese Wallet ist bereits mit einem anderen Konto verknüpft.",
    wallet_change_requires_unlink:
      "Trennen Sie zuerst Ihre aktuelle Wallet, bevor Sie eine andere verbinden.",
  },
}
