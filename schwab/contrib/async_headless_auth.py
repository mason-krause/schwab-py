import asyncio
import os
from pyotp import TOTP
from schwab.auth import _fetch_and_register_token_from_redirect
from playwright.async_api import async_playwright
from authlib.integrations.httpx_client import AsyncOAuth2Client


async def get_redirect_url(authorize_url, username, password, totp_secret=None, headless_login=True):
    if totp_secret:
        totp = TOTP(totp_secret)
    async with async_playwright() as p:    
        try:
            browser = await p.firefox.launch(headless=headless_login)
            page = await browser.new_page()
            await page.goto(authorize_url)
            await page.locator('#loginIdInput').fill(username)
            await page.locator('#passwordInput').fill(password)
            await page.locator('#btnLogin').click()
            if totp_secret:
                await page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/placeholder')
                await page.locator('#placeholderCode').fill(totp.now())
                await page.locator('#continueButton').click()
            await page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/cag')
            await page.locator('#acceptTerms').click()
            await page.locator('#submit-btn').click()
            await page.locator('#agree-modal-btn-').click()
            await page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/account')
            await page.locator('#submit-btn').click()
            await page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/confirmation')
            await page.locator('#cancel-btn').click()
            url = ''
            while '127.0.0.1' not in url:
                url = await page.evaluate('() => window.location.href')
                await asyncio.sleep(.1)
            await browser.close()
            return url
        except Exception as e: # close browser even if there's an exception
            await browser.close()
            return
        
################################################################################
# client_from_user_creds


async def client_from_env_vars(token_path, api_key, app_secret, enforce_enums=True,
                               token_write_func=None, headless_login=True):
    '''
    Automatically logs in into Schwab account with headless Firefox using user 
    credentials supplied by preset environment variables: SCHWAB_USERNAME, 
    SCHWAB_PASSWORD, and SCHWAB_TOTP_TOKEN and returns a client object.

    :param token_path: Path to which the new token will be written. If the token
                       file already exists, it will be overwritten with a new
                       one. Updated tokens will be written to this path as well.
    :param api_key: Your Schwab application's app key.
    :param app_secret: Application secret. Provided upon :ref:`app approval 
                       <approved_pending>`.
    :param enforce_enums: Set it to ``False`` to disable the enum checks on ALL
                          the client methods. Only do it if you know you really
                          need it. For most users, it is advised to use enums
                          to avoid errors.
    :param token_write_func: Function that writes the token on update. Will be
                             called whenever the token is updated, such as when
                             it is refreshed. See the above-mentioned example 
                             for what parameters this method takes.
    :param headless_login: Set it to ``False`` to show the browser when logging
                          in to your Schwab account. This is useful for debugging
                          login issues.
    '''
    username = os.getenv('SCHWAB_USERNAME', '')
    password = os.getenv('SCHWAB_PASSWORD', '')
    totp_secret = os.getenv('SCHWAB_TOTP_TOKEN', '')

    temp_client = AsyncOAuth2Client(
        client_id = api_key,
        client_secret = app_secret,
        redirect_uri = 'https://127.0.0.1')
    authorize_url, state = await temp_client.create_authorization_url(
        'https://api.schwabapi.com/v1/oauth/authorize')
    redirect_url = await get_redirect_url(authorize_url, username, password, totp_secret, headless_login)

    return _fetch_and_register_token_from_redirect(
        temp_client, redirect_url, api_key, app_secret, token_path, token_write_func, True, 
        enforce_enums)