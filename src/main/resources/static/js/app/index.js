const main = {
    init: function() {
        $('#btn-save').on('click', () => {
            this.save()
        })
        $('#btn-update').on('click', () => {
            this.update()
        })
        $('#btn-delete').on('click', () => {
            this.delete()
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
    },
    update: function() {
        const data = {
            title: $('#title').val(),
            content: $('#content').val(),
        }

        const id = $('#id').val();

        $.ajax({
            type: 'PUT',
            url: '/api/v1/posts/'+id,
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: JSON.stringify(data)
        }).done(function() {
            alert('success')
            window.location.href = '/'
        }).fail(function(error) {
            alert(JSON.stringify(error))
        })

    },
    delete: function() {
        const id = $('#id').val();

        $.ajax({
            type: 'DELETE',
            url: '/api/v1/posts/'+id,
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
        }).done(function() {
            alert('success')
            window.location.href = '/'
        }).fail(function(error) {
            alert(JSON.stringify(error))
        })

    }
}

main.init()