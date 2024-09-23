﻿using System;
using PgpCoreM.Models;

namespace PgpCoreM.Extensions
{
    internal static class DisposableExtensions
    {
        /// <seealso href="https://github.com/reactiveui/ReactiveUI/blob/main/src/ReactiveUI/Mixins/DisposableMixins.cs#L28">
        /// Adapted from ReactiveUI.
        /// </seealso>
        public static T DisposeWith<T>(this T @this, CompositeDisposable disposables)
            where T : IDisposable
        {
            if (@this == null)
                throw new ArgumentNullException(nameof(@this));
            if (disposables == null)
                throw new ArgumentNullException(nameof(disposables));

            disposables.Add(@this);
            return @this;
        }
    }
}
