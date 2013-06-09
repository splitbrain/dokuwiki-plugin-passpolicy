jQuery(function(){

    var $passfield = jQuery('form input[type=password][name=pass], form input[type=password][name=newpass]');
    if(!$passfield.length) return;

    /**
     * Scores a password's strength on an open scale
     *
     * @author Toms Baugis
     * @link http://stackoverflow.com/a/11268104
     * @param string pass
     * @return int
     */
    function scorePassword(pass) {
        var score = 0;
        if (!pass)
            return score;

        // award every unique letter until 5 repetitions
        var letters = new Object();
        for (var i=0; i<pass.length; i++) {
            letters[pass[i]] = (letters[pass[i]] || 0) + 1;
            score += 5.0 / letters[pass[i]];
        }

        // bonus points for mixing it up
        var variations = {
            digits: /\d/.test(pass),
            lower: /[a-z]/.test(pass),
            upper: /[A-Z]/.test(pass),
            nonWords: /\W/.test(pass),
        };

        variationCount = 0;
        for (var check in variations) {
            variationCount += (variations[check] == true) ? 1 : 0;
        }
        score += (variationCount - 1) * 10;

        return parseInt(score);
    }

    var indicator = document.createElement('p');
    indicator.id = 'passpolicy__indicator';
    $passfield.after(indicator);

    /**
     * Apply scoring
     */
    function scoreit(){
        var score = scorePassword($passfield.val());

        if (score > 80) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength3;
            indicator.className = 'passpolicy_strength3';
        } else if (score > 60) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength2;
            indicator.className = 'passpolicy_strength2';
        } else if (score >= 30) {
            indicator.innerHTML = LANG.plugins.passpolicy.strength1;
            indicator.className = 'passpolicy_strength1';
        } else {
            indicator.innerHTML = LANG.plugins.passpolicy.strength0;
            indicator.className = 'passpolicy_strength0';
        }
    }

    $passfield.keyup(scoreit);
    $passfield.blur(scoreit);

});