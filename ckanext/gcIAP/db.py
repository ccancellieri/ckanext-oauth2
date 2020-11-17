# This file is part of FAO GCIAP Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3


import sqlalchemy as sa

UserToken = None

def init_db(model):

    global UserToken
    if UserToken is None:

        class _UserToken(model.DomainObject):

            @classmethod
            def by_user_name(cls, user_name):
                return model.Session.query(cls).filter_by(user_name=user_name).first()

        UserToken = _UserToken

        user_token_table = sa.Table('user_token', model.meta.metadata,
            sa.Column('user_name', sa.types.UnicodeText, primary_key=True),
            sa.Column('access_token', sa.types.UnicodeText)
        )

        # Create the table only if it does not exist
        user_token_table.create(checkfirst=True)

        model.meta.mapper(UserToken, user_token_table)
