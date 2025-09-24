from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self,email,password):
        if not email:
            raise ValueError('이메일 작성 똑디해라 마!')

        user = self.model(
            email=self.normalize_email(email)
        )
        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self,email,password):
        user = self.create_user(email,password)
        user.is_admin = True
        user.is_active = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email',
        unique=True,
    )
    is_active =  models.BooleanField(default=True)
    is_admin =  models.BooleanField(default=False)
    nickname = models.CharField('nickname', max_length=64, unique=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = '유저'
        verbose_name_plural = f'{verbose_name} 목록 '


    def get_full_name(self):
        return self.nickname

    def get_short_name(self):
        return self.nickname

    def __str__(self):
        return self.nickname

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

    @property
    def is_superuser(self):
        return self.is_admin