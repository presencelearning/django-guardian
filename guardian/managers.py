from __future__ import unicode_literals
from django.db import models
from django.db.models import Q
from django.db.models import QuerySet
from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type
from guardian.exceptions import ObjectNotPersisted
from guardian.models import Permission

import warnings


class BaseObjectPermissionManager(models.Manager):

    @property
    def user_or_group_field(self):
        try:
            self.model._meta.get_field('user')
            return 'user'
        except models.fields.FieldDoesNotExist:
            return 'group'

    def is_generic(self):
        try:
            self.model._meta.get_field('object_pk')
            return True
        except models.fields.FieldDoesNotExist:
            return False

    def _perm_kwargs(self, permission, user_or_group, obj, ctype=None, origin=None):
        if ctype is None:
            ctype = get_content_type(obj)
        kwargs = {
            'permission': permission,
            self.user_or_group_field: user_or_group,
        }
        if self.is_generic():
            kwargs['content_type'] = ctype
            kwargs['object_pk'] = obj.pk
        else:
            kwargs['content_object'] = obj
        if origin:
            kwargs['origin'] = origin
        return kwargs

    def assign_perm(self, perm, user_or_group, obj, origin=None):
        """
        Assigns permission with given ``perm`` for an instance ``obj`` and
        ``user``.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)
        ctype = get_content_type(obj)
        if not isinstance(perm, Permission):
            permission = Permission.objects.get(content_type=ctype, codename=perm)
        else:
            permission = perm

        kwargs = self._perm_kwargs(permission, user_or_group, obj, ctype, origin)
        obj_perm, _ = self.get_or_create(**kwargs)
        return obj_perm

    def assign_perm_from_origin(self, perm, origin):
        return self.assign_perm(perm, origin.user, origin.content_object, origin)

    def bulk_assign_perm(self, perm, user_or_group, queryset, origin=None):
        """
        Bulk assigns permissions with given ``perm`` for an objects in ``queryset`` and
        ``user_or_group``.
        """

        ctype = get_content_type(queryset.model)
        if not isinstance(perm, Permission):
            permission = Permission.objects.get(content_type=ctype, codename=perm)
        else:
            permission = perm

        checker = ObjectPermissionChecker(user_or_group)
        checker.prefetch_perms(queryset)

        assigned_perms = []
        for instance in queryset:
            if not checker.has_perm(permission.codename, instance):
                kwargs = self._perm_kwargs(permission, user_or_group, instance, ctype, origin)
                assigned_perms.append(self.model(**kwargs))
        self.bulk_create(assigned_perms)

        return assigned_perms

    def bulk_assign_perm_from_origins(self, perm, origins):
        """
        Bulk assigns permissions with given ``perm`` for the user and content_object in origins.
        The content_objects must be of the same type.
        """
        if len(origins) == 0:
            return []

        if isinstance(origins, QuerySet):
            origins = origins.select_related('content_object')

        ctype = get_content_type(origins[0].content_object)

        if not isinstance(perm, Permission):
            permission = Permission.objects.get(content_type=ctype, codename=perm)
        else:
            permission = perm

        by_user = {o.user: [] for o in origins}
        for o in origins:
            by_user[o.user].append(o)

        assigned_perms = []
        for user in by_user:
            objects = by_user[user]

            checker = ObjectPermissionChecker(user)
            checker.prefetch_perms([o.content_object for o in objects])

            for origin in objects:
                instance = origin.content_object
                if not checker.has_perm('{}.{}'.format(permission.content_type.name, permission.codename), instance):
                    kwargs = self._perm_kwargs(permission, user, instance, ctype, origin)
                    assigned_perms.append(self.model(**kwargs))
        self.bulk_create(assigned_perms)

        return assigned_perms

    def assign(self, perm, user_or_group, obj):
        """ Depreciated function name left in for compatibility"""
        warnings.warn("UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.", DeprecationWarning)
        return self.assign_perm(perm, user_or_group, obj)

    def remove_perm(self, perm, user_or_group, obj):
        """
        Removes permission ``perm`` for an instance ``obj`` and given ``user_or_group``.

        Please note that we do NOT fetch object permission from database - we
        use ``Queryset.delete`` method for removing it. Main implication of this
        is that ``post_delete`` signals would NOT be fired.
        """
        if getattr(obj, 'pk', None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first"
                                     % obj)

        filters = Q(**{self.user_or_group_field: user_or_group})

        if isinstance(perm, Permission):
            filters &= Q(permission=perm)
        else:
            filters &= Q(permission__codename=perm,
                         permission__content_type=get_content_type(obj))

        if self.is_generic():
            filters &= Q(object_pk=obj.pk)
        else:
            filters &= Q(content_object__pk=obj.pk)
        return self.filter(filters).delete()

    def bulk_remove_perm(self, perm, user_or_group, queryset):
        """
        Removes permission ``perm`` for a ``queryset`` and given ``user_or_group``.

        Please note that we do NOT fetch object permission from database - we
        use ``Queryset.delete`` method for removing it. Main implication of this
        is that ``post_delete`` signals would NOT be fired.
        """
        filters = Q(**{self.user_or_group_field: user_or_group})

        if isinstance(perm, Permission):
            filters &= Q(permission=perm)
        else:
            ctype = get_content_type(queryset.model)
            filters &= Q(permission__codename=perm,
                         permission__content_type=ctype)

        if self.is_generic():
            filters &= Q(object_pk__in=[str(pk) for pk in queryset.values_list('pk', flat=True)])
        else:
            filters &= Q(content_object__in=queryset)

        return self.filter(filters).delete()


class UserObjectPermissionManager(BaseObjectPermissionManager):
    pass


class GroupObjectPermissionManager(BaseObjectPermissionManager):
    pass
