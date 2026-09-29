import pytest

from script_inventory.detect import from_body, from_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://code.jquery.com/jquery-3.4.1.min.js", [("jquery", "3.4.1")]),
        ("https://code.jquery.com/jquery-1.12.4.slim.min.js", [("jquery", "1.12.4")]),
        ("https://code.jquery.com/ui/1.12.1/jquery-ui.min.js", [("jquery-ui", "1.12.1")]),
        ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js", [("jquery", "3.6.0")]),
        ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/js/bootstrap.min.js", [("bootstrap", "4.3.1")]),
        ("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js", [("lodash", "4.17.15")]),
        ("https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js", [("angularjs", "1.8.2")]),
        ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js", [("bootstrap", "5.3.3")]),
        ("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js", [("popper", "2.11.8")]),
        ("https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js", [("react-dom", "18.2.0")]),
        ("https://unpkg.com/vue@2.6.14/dist/vue.js", [("vue", "2.6.14")]),
        ("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js", [("bootstrap", "3.3.7")]),
        ("https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", [("jquery", "3.7.1")]),
        ("https://example.com/js/moment-2.29.1.min.js", [("moment", "2.29.1")]),
        ("https://example.com/js/jquery.min.js", [("jquery", None)]),
        ("https://example.com/js/app.4f2a9c.js", []),
        ("https://www.googletagmanager.com/gtag/js?id=G-XXXX", []),
    ],
)
def test_from_url(url, expected):
    assert from_url(url) == expected


def test_banners():
    assert from_body("/*! jQuery v3.4.1 | (c) JS Foundation */") == [("jquery", "3.4.1")]
    assert from_body("/*!\n * jQuery JavaScript Library v1.12.4\n */") == [("jquery", "1.12.4")]
    assert from_body("/*! jQuery UI - v1.13.2 - 2022-07-14 */") == [("jquery-ui", "1.13.2")]
    assert from_body("/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)\n  */") == [("bootstrap", "4.3.1")]
    assert from_body("/**\n * @license AngularJS v1.8.2\n */") == [("angularjs", "1.8.2")]
    assert from_body("/*!\n * Vue.js v2.6.14\n */") == [("vue", "2.6.14")]


def test_lodash_banner_does_not_report_underscore():
    body = ("/**\n * @license\n * Lodash <https://lodash.com/>\n * Based on Underscore.js 1.8.3\n */\n"
            ";(function(){var VERSION = '4.17.15';})();")
    assert from_body(body) == [("lodash", "4.17.15")]
    minified = '/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */\n' \
               ';(function(){function n(){}var u,i="4.17.21",o=200;})();'
    assert from_body(minified) == [("lodash", "4.17.21")]


def test_underscore_banner():
    assert from_body("//     Underscore.js 1.13.6\n//     https://underscorejs.org\n") == [("underscore", "1.13.6")]


def test_moment_and_react():
    assert from_body("//! moment.js\n//! version : 2.29.1\n") == [("moment", "2.29.1")]
    assert from_body('//! moment.js\n!function(){}();e.version="2.18.1";') == [("moment", "2.18.1")]
    assert from_body("/** @license React v17.0.2\n * react.production.min.js\n */") == [("react", "17.0.2")]
    body = '/**\n * @license React\n * react-dom.production.min.js\n */\n;exports.version="18.2.0";'
    assert from_body(body) == [("react-dom", "18.2.0")]


def test_plain_code_is_not_a_library():
    assert from_body("window.dataLayer = window.dataLayer || [];") == []
