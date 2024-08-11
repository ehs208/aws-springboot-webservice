var main = {
    init: function() {
        $('#btn-save').on('click', () => {
            this.save()
        })
    },
    save: async function() {
        const data = {
            title: $('#title').val(),
            author: $('#author').val(),
            content: $('#content').val(),
        }

        $.ajax({
            type: 'POST',
            url: '/api/v1/posts',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: JSON.stringify(data)
        }).done(function() {
            alert('success')
            window.location.href = '/'
        }).fail(function(error) {
            alert(JSON.stringify(error))
        })
    }}

main.init()