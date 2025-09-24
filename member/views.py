# member/views.py

from django.contrib.auth import get_user_model,login
from django.core.signing import TimestampSigner,SignatureExpired
from django.core import signing
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse,reverse_lazy
from django.views.generic import FormView
from member.form import SingupForm,LoginForm
from config import settings
from django.http import Http404, HttpResponseRedirect

User = get_user_model()

class SignupView(FormView):
    template_name = 'auth/signup.html'
    form_class = SingupForm

    def form_valid(self, form):
        user = form.save()
        signer = TimestampSigner()
        signed_user_email = signer.sign(user.email)
        signer_dump = signing.dumps(signed_user_email)

        url = f'{self.request.scheme}://{self.request.META["HTTP_HOST"]}/verify/?code={signer_dump}'
        if settings.DEBUG:
            print(url)

        return render(
            self.request,
            template_name='auth/signup_done.html',
            context={'user': user}
        )


def verify_email(request):
    code = request.GET.get('code', '')
    signer = TimestampSigner()
    try:
        decoded_user_email = signing.loads(code)
        email = signer.unsign(decoded_user_email, max_age=60 * 30)
    except (TypeError, SignatureExpired):
        return render(request, 'auth/not_verified.html')

    user = get_object_or_404(User, email=email, is_active=False)
    user.is_active = True
    user.save()
    return redirect(reverse('login'))


class LoginView(FormView):
    template_name = 'auth/login.html'
    form_class = LoginForm
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        user = form.user
        login(self.request, user)

        next_page = self.request.GET.get('next')
        if next_page:
            return HttpResponseRedirect(next_page)

        return HttpResponseRedirect(self.get_success_url())
