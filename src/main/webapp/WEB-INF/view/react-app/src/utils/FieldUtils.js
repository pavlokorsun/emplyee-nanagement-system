import React from 'react';

export default class FieldUtils {
    static cleanUpField(currentObject, field) {
        currentObject.refs[field].state.value = '';
    }
}

