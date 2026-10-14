// rememberme: Settings -> Remembered devices page.

if (window.rcmail) {
    rcmail.addEventListener('plugin.rememberme_reload', function () {
        location.reload();
    });

    rcmail.addEventListener('init', function () {
        $('.rememberme-revoke').on('click', function () {
            var button = this,
                current = $(button).data('current') == 1,
                send = function () {
                    rcmail.http_post('plugin.rememberme.revoke', {_id: $(button).data('id')}, rcmail.set_busy(true, 'loading'));
                };

            // Forgetting this browser also means its current session can't
            // be kept alive any more, so say so first.
            if (current) {
                rcmail.confirm_dialog(rcmail.gettext('rememberme.confirmthisdevice'), 'rememberme.signout', send);
            } else {
                send();
            }
        });

        $('#rememberme-revoke-others').on('click', function () {
            rcmail.confirm_dialog(rcmail.gettext('rememberme.confirmothers'), 'rememberme.signoutothers', function () {
                rcmail.http_post('plugin.rememberme.revoke', {_others: 1}, rcmail.set_busy(true, 'loading'));
            });
        });
    });
}
