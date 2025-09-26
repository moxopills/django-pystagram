from django.contrib import admin

from post.models import PostImage, Post


class PostImageInline(admin.TabularInline):
    model = PostImage
    fields = ['image']
    extra = 1

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    inlines = [PostImageInline]
