import time

from django.conf import settings
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date

try:
    from importlib import import_module
except ImportError:
    from django.utils.importlib import import_module

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    class MiddlewareMixin(object):
        pass


class SessionMiddleware(MiddlewareMixin):
    """
    Middleware that provides ip and user_agent to the session store.
    """
    def process_request(self, request):
        engine = import_module(settings.SESSION_ENGINE)
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
        client = None
        if 'HTTP_SEC_CH_UA' in request.META:
            client = {
                'platform': request.META.get('HTTP_SEC_CH_UA_PLATFORM', '').replace('"', '').strip(),
                'platform_version': request.META.get('HTTP_SEC_CH_UA_PLATFORM_VERSION', '').replace('"', '').strip(),
                'model': request.META.get('HTTP_SEC_CH_UA_MODEL', '').replace('"', '').strip(),
                'is_mobile': request.META.get('HTTP_SEC_CH_UA_MOBILE', '?0') == '?1',
            }
        request.session = engine.SessionStore(
            ip=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=session_key,
            client=client
        )

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
        except AttributeError:
            pass
        else:
            if accessed:
                patch_vary_headers(response, ('Cookie',))
            if modified or settings.SESSION_SAVE_EVERY_REQUEST:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = http_date(expires_time)
                # Save the session data and refresh the client cookie.
                # Skip session save for 500 responses, refs #3881.
                if response.status_code != 500:
                    # if '_auth_user_id' not in request.session and request.user.is_authenticated:
                    #     request.session['_auth_user_id'] = request.user.pk
                    request.session.save()
                    response.set_cookie(
                        settings.SESSION_COOKIE_NAME,
                        request.session.session_key,
                        max_age=max_age,
                        expires=expires,
                        domain=settings.SESSION_COOKIE_DOMAIN,
                        path=settings.SESSION_COOKIE_PATH,
                        secure=settings.SESSION_COOKIE_SECURE or None,
                        httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                        samesite=settings.SESSION_COOKIE_SAMESITE,
                    )
        response['Accept-CH'] = 'Sec-CH-UA-Mobile, Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA'
        return response
