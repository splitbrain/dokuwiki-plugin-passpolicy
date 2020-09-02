jQuery(function () {

    var $passfield = jQuery('form input[type=password][name=pass], ' +
        'form input[type=password][name=newpass], ' +
        '#add_userpass, #modify_userpass');
    if (!$passfield.length) return;

    /**
     * Scores a password's strength on an open scale
     *
     * @author Toms Baugis
     * @link http://stackoverflow.com/a/11268104
     * @param pass string
     * @return int
     */
    function scorePassword(pass) {
        var score = 0;
        if (!pass)
            return score;

        // award every unique letter until 5 repetitions
        var letters = {};
        for (var i = 0; i < pass.length; i++) {
            letters[pass[i]] = (letters[pass[i]] || 0) + 1;
            score += 5.0 / letters[pass[i]];
        }

        // bonus points for mixing it up
        var variations = {
            digits: /\d/.test(pass),
            lower: /[a-z]/.test(pass),
            upper: /[A-Z]/.test(pass),
            nonWords: /\W/.test(pass)
        };

        var variationCount = 0;
        for (var check in variations) {
            variationCount += (variations[check]) ? 1 : 0;
        }
        score += (variationCount - 1) * 10;

        return parseInt(score);
    }

    /**
     * check policy
     *
     * @param $field object jQuery object of the password field
     * @param indicator DomObject where the output should go
     */
    function checkpolicy($field, indicator) {
        var pass = $field.val();
        var user = jQuery('form input[type=text][name=login]').val();

        jQuery.post(
            DOKU_BASE + 'lib/exe/ajax.php',
            {
                call: 'plugin_passpolicy',
                pass: pass,
                user: user
            },
            function (response) {
                if (response === '1') {
                    scoreit($field, indicator, true);
                } else {
                    scoreit($field, indicator, false);
                }
            }
        );
    }

    /**
     * Apply scoring
     *
     * @param {object} $field jQuery object of the password field
     * @param {Node} indicator where the output should go
     * @param {bool} policy true if the policy is met
     */
    function scoreit($field, indicator, policy) {
        var score = scorePassword($field.val());

        if (score > 80) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength3;
            indicator.className = 'passpolicy_strength3';
        } else if (score >= 60) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength2;
            indicator.className = 'passpolicy_strength2';
        } else if (score >= 30) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength1;
            indicator.className = 'passpolicy_strength1';
        } else {
            indicator.innerHTML = LANG.plugins.passpolicy.strength0;
            indicator.className = 'passpolicy_strength0';
        }

        if (!policy) {
            indicator.innerHTML += LANG.plugins.passpolicy.nopolicy;
            indicator.className = 'passpolicy_strength0';
        }
    }

    /**
     * Attach strength tester at the found password fields
     */
    $passfield.each(function () {
        var $field = jQuery(this);

        var indicator = document.createElement('p');
        indicator.className = 'passpolicy__indicator';

        $field.after(indicator);
        $field.keyup(function () {
            checkpolicy($field, indicator)
        });
        $field.blur(function () {
            checkpolicy($field, indicator)
        });
    });


});
