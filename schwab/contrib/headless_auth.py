import asyncio as asynciolib
import time
from pyotp import TOTP
from schwab.auth import _fetch_and_register_token_from_redirect
from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright
from authlib.integrations.httpx_client import AsyncOAuth2Client, OAuth2Client


async def async_get_redirect_url(authorize_url, username, password, totp_secret=None, headless_login=True):
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
            await asynciolib.sleep(1)
            # await page.wait_for_function("() => window.location.href.includes('127.0.0.1')")
            url = await page.evaluate('() => window.location.href')
            await browser.close()
            return url
        except Exception as e: # close browser even if there's an exception
            await browser.close()
            return

def get_redirect_url(authorize_url, username, password, totp_secret=None, headless_login=True):
    if totp_secret:
        totp = TOTP(totp_secret)
    with sync_playwright() as p:    
        try:
            browser = p.firefox.launch(headless=headless_login)
            page = browser.new_page()
            page.goto(authorize_url)
            page.locator('#loginIdInput').fill(username)
            page.locator('#passwordInput').fill(password)
            page.locator('#btnLogin').click()
            if totp_secret:
                page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/placeholder')
                page.locator('#placeholderCode').fill(totp.now())
                page.locator('#continueButton').click()
            page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/cag')
            page.locator('#acceptTerms').click()
            page.locator('#submit-btn').click()
            page.locator('#agree-modal-btn-').click()
            page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/account')
            page.locator('#submit-btn').click()
            page.wait_for_url('https://sws-gateway.schwab.com/ui/host/#/third-party-auth/confirmation')
            page.locator('#cancel-btn').click()
            time.sleep(1)
            # await page.wait_for_function("() => window.location.href.includes('127.0.0.1')")
            url = page.evaluate('() => window.location.href')
            browser.close()
            return url
        except Exception as e: # close browser even if there's an exception
            browser.close()
            return

################################################################################
# client_from_user_creds


def client_from_user_creds(username, password, token_path, api_key, app_secret, asyncio=False,
                           enforce_enums=True, token_write_func=None, totp_secret=None, 
                           headless_login=True):
    '''
    Returns a session from an existing token file. The session will perform
    an auth refresh as needed. It will also update the token on disk whenever
    appropriate.

    :param username: Your Schwab brokerage account username 
    :param password: Your Schwab brokerage account username 
    :param token_path: Path to which the new token will be written. If the token
                       file already exists, it will be overwritten with a new
                       one. Updated tokens will be written to this path as well.
    :param api_key: Your Schwab application's app key.
    :param app_secret: Application secret. Provided upon :ref:`app approval 
                       <approved_pending>`.
    :param asyncio: If set to ``True``, this will enable async support allowing
                    the client to be used in an async environment. Defaults to
                    ``False``
    :param enforce_enums: Set it to ``False`` to disable the enum checks on ALL
                          the client methods. Only do it if you know you really
                          need it. For most users, it is advised to use enums
                          to avoid errors.
    :param token_write_func: Function that writes the token on update. Will be
                             called whenever the token is updated, such as when
                             it is refreshed. See the above-mentioned example 
                             for what parameters this method takes.
    :param totp_secret: The secret key for your 2FA TOTP. This can be generated
                        with tools like python-vipaccess which allow you to 
                        bring your own authenticator app to Schwab for 2FA.
    :param headless_login: Set it to ``False`` to show the browser when logging
                          in to your Schwab account. This is useful for debugging
                          login issues.
    '''

    if asyncio:
        client_class = AsyncOAuth2Client
        get_url_func = async_get_redirect_url
    else:
        client_class = OAuth2Client
        get_url_func = get_redirect_url
    temp_client = client_class(
        client_id = api_key,
        client_secret = app_secret,
        redirect_uri = 'https://127.0.0.1')
    authorize_url, state = temp_client.create_authorization_url(
        'https://api.schwabapi.com/v1/oauth/authorize')
    redirect_url = get_url_func(authorize_url, username, password, totp_secret, headless_login)

    return _fetch_and_register_token_from_redirect(
        temp_client, redirect_url, api_key, app_secret, token_path, token_write_func, asyncio, 
        enforce_enums)